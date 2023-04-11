#pragma once
#include "net.h"
#include <iostream>
#include <cstring>
#include <assert.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>
#include <functional>

class ATP
{
public:
    ATP(const char *name)
    {
        device = open_pcap(name);
    }
    void work()
    {
        send_thread = std::thread(&ATP::run_send, this);
        recv_thread = std::thread(&ATP::run_recv, this);
    }
    void stop()
    {
        send_thread.join();
        recv_thread.join();
    }
    // 接口

    int init_conn(uint32_t src_ip, uint32_t dst_ip) // conn_id由发送方确定
    {
        for (int i = 1; i <= MAX_CON_NUM; i++)
        {
            if (conn_t[i].conn_id == 0)
            {
                conn_t[i].src_ip = src_ip;
                conn_t[i].dst_ip = dst_ip;
                conn_t[i].conn_id = i;
                socket_map[conn_t[i]] = i;
                return i;
            }
        }
        return -1;
    }
    //
    int accept_conn(uint32_t conn_id, uint32_t src_ip, uint32_t dst_ip)
    {
        auto ans = socket_map.find(_conn_t(0, src_ip, dst_ip));
        if (ans != socket_map.end())
        {
            int temp = ans->second;
            socket_map.erase(ans);
            socket_map.insert({_conn_t(conn_id, src_ip, dst_ip), temp});
            return temp;
        }
        else if (conn_id == 0) // 准备接受这个地址信息
        {
            for (int i = 1; i <= MAX_CON_NUM; i++)
            {
                if (conn_t[i].conn_id == 0)
                {
                    conn_t[i].src_ip = src_ip;
                    conn_t[i].dst_ip = dst_ip;
                    conn_t[i].conn_id = conn_id;
                    socket_map[conn_t[i]] = i;
                    return i;
                }
            }
        }
        return -1;
    }

    void close_conn(int socket)
    {
        conn_t[socket].conn_id = -1;
        recv_state[socket].close(); // 给对面发送一个结束的信号

        auto ans = socket_map.find(conn_t[socket]);
        if (ans != socket_map.end())
            socket_map.erase(ans);
    }

    int send(uint32_t socket, const char *addr,uint32_t size)
    { // 阻塞的端口设计。
        uint32_t ans = 0;
        while (ans < size)
        { // 对很大发送数据分割为多次发送任务。
            int temp = send_state.buff.Write(addr + ans, size - ans);
            ans += temp;
            std::cout << "send task emplace" << std::endl;
            send_state.tasks.emplace(socket, temp);
        }
        return size;
    }

    int recv(uint32_t socket, char *addr,uint32_t size)
    { // 构建recv_state
        // 非阻塞接口等待接受到信息，接受到足够的信息，除非断开连接
        int ans = 0;
        ans = recv_state[socket].buff.Read(addr, size);
        // 接受数据 发送ack，边接受边回应
        return ans;
    }

private:
    // 线程
    std::thread send_thread;
    std::thread recv_thread;

    // 网卡
    pcap_t *device;

    // 发送
    _send_state send_state;

    std::mutex ackwin_lock;

    // 接受
    _recv_state recv_state[MAX_CON_NUM];

    // socket->conn_t
    _conn_t conn_t[MAX_CON_NUM + 1];
    // conn_t->socket，内部是安全的，但对接口不是线程安全的
    std::map<_conn_t, uint32_t> socket_map;
    void run_send()
    {
        std::cout << "run send thread\n";
        // 这里开启一个线程专门用于处理task队列，并且通过线程间通信得到成功返回

        send_state.tasks.wait_and_pop(send_state.current_task);
        std::cout << "get first cur_task " << send_state.current_task.size << std::endl;
        while (true)
        {
            _task *cur_task = &send_state.current_task;
            // 超时重传的数据,加入缓冲区
            for (uint32_t seq = send_state.last_acked.load() + 1; seq <= send_state.last_sent.load(); seq++)
            {
                auto tmp_window = seq % (2 * MAX_WND_SIZE);
                auto now = steady_clock::now();
                // 500ms && == false
                if (duration_cast<milliseconds>(now - send_state.send_time[tmp_window]).count() > 1000 && send_state.ack_window[tmp_window] == false)
                {
                    std::cout << "cur_task timeout resend " << seq << '\n';
                    send_state.send_time[tmp_window] = now;
                    int ret = pcap_inject(device, &send_state.send_window[tmp_window], send_state.send_window[tmp_window].ip_head.length);
                    if (ret == -1)
                    {
                        std::cout << pcap_geterr(device) << '\n'
                                  << "len " << send_state.send_window[tmp_window].ip_head.length << '\n';
                    }
                }
            }
            // 打包到滑动窗口并重新发送
            send_encode_packet(cur_task);

            // 等待回应的ack，更新last_acked
            while (send_state.last_acked < send_state.last_sent)
            {
                int seq = send_state.last_acked.load() + 1;
                if (send_state.ack_window[seq % (2 * MAX_WND_SIZE)])
                {
                    send_state.ack_window[seq % (2 * MAX_WND_SIZE)] = false;
                    send_state.last_acked++;
                }
                else
                    break;
            }
            if (send_state.last_acked.load() == send_state.last_seq_of_current_task)
            {
                send_state.tasks.wait_and_pop(send_state.current_task);
            }
        }
    }
    void send_encode_packet(_task *cur_task)
    {
        while (cur_task->size > 0 && send_state.last_sent.load() < send_state.last_acked.load() + MAX_WND_SIZE * 2)
        {
            send_state.last_sent++;
            std::cout << "send encode packet " << send_state.last_sent << '\n';
            // 装包
            auto tmp_window = send_state.last_sent.load() % (2 * MAX_WND_SIZE);

            incp_header_t &incp_head = send_state.send_window[tmp_window].incp_head;
            incp_head.type = INCP_DATA;
            if (MSS <= cur_task->size)
            {
                incp_head.length = MSS + sizeof(incp_header_t);
                cur_task->size -= MSS;
            }
            else
            {
                incp_head.length = cur_task->size + sizeof(incp_header_t);
                send_state.last_seq_of_current_task = send_state.last_sent.load();
                cur_task->size = 0;
            }
            incp_head.seq_num = send_state.last_sent.load();
            //incp_head.window_size; // 告知自己的接受缓冲区
            incp_head.conn_num = conn_t[cur_task->socket].conn_id;

            ip_header_t &ip_head = send_state.send_window[tmp_window].ip_head;
            ip_head.version = 0;
            ip_head.length = incp_head.length + sizeof(ip_head);
            ip_head.src_ip = conn_t[cur_task->socket].src_ip;
            ip_head.dst_ip = conn_t[cur_task->socket].dst_ip;
            ip_head.ttl = 0x0f;
            ip_head.checksum = 0;
            // 由于send接口写入缓冲区的，正常情况一定存在相应的数据

            int len = incp_head.length - sizeof(incp_header_t);
            for (int i = 0; i < len;)
            {
                i += send_state.buff.Read(send_state.send_window[tmp_window].data + i, len - i);
            }
            // 计算校验码
            ip_head.checksum = compute_checksum(&send_state.send_window[tmp_window], ip_head.length);
            // 发送
            send_state.send_time[tmp_window] = steady_clock::now();
            int ret = pcap_inject(device, &send_state.send_window[tmp_window], send_state.send_window[tmp_window].ip_head.length);
            if (ret == -1)
            {
                std::cout << pcap_geterr(device);
            }
        }
    }

    void recv_handle(const struct pcap_pkthdr *pkthdr, const u_char *packet)
    {
        // 接受的数据到缓冲区
        // 默认为整数个ip片，解析ip片
        recv_pack((ip_packet *)packet);
        return;
    }
    // 打包到滑动窗口发送
    void run_recv()
    {
        std::cout << "run recv thread\n";
        pcap_handler callback = (pcap_handler)&ATP::recv_handle;
        pcap_loop(device, -1, callback, (u_char *)this);
    }

    void respond_ack(ip_packet *cur_packet)
    {

        ip_packet ack_packet;
        incp_header_t &incp_head = ack_packet.incp_head;
        incp_head.type = INCP_ACK;
        incp_head.length = sizeof(incp_head);
        incp_head.ack_num = cur_packet->incp_head.seq_num;
        incp_head.conn_num = cur_packet->incp_head.conn_num;

        ip_header_t &ip_head = ack_packet.ip_head;
        ip_head.version = cur_packet->ip_head.version;
        ip_head.length = incp_head.length + sizeof(ip_head);
        ip_head.src_ip = cur_packet->ip_head.dst_ip;
        ip_head.dst_ip = cur_packet->ip_head.src_ip;
        ip_head.ttl = 0x0f;
        ip_head.checksum = 0;

        ip_head.checksum = compute_checksum(&ack_packet, ip_head.length);
        pcap_inject(device, &ack_packet, ip_head.length);
        std::cout << "respond ack " << incp_head.ack_num << '\n';
    }
    int recv_pack(ip_packet *cur_packet)
    {
        // 处理单个ip_packet包 读入到接受窗口,处理data

        uint16_t check = cur_packet->ip_head.checksum;
        cur_packet->ip_head.checksum = 0;
        if (compute_checksum(cur_packet, cur_packet->ip_head.length) == check)
        { // 查找对应连接
            int socket;
            auto ans = socket_map.find(_conn_t(cur_packet->incp_head.conn_num, cur_packet->ip_head.dst_ip, cur_packet->ip_head.src_ip));
            if (ans != socket_map.end())
            {
                socket = ans->second;
                std::cout << "socket " << socket << " recv...\n";
            }
            else
            { // 接受连接
                socket = accept_conn(cur_packet->incp_head.conn_num, cur_packet->ip_head.dst_ip, cur_packet->ip_head.src_ip);
                std::cout << "ready to build a connect\n socket " << socket << std::endl;
                if (socket == -1)
                {
                    std::cout << "don't establish a connect\n";
                    return 0; // 丢弃这个包
                }
            }
            _recv_state &cur_recv_state = recv_state[socket];

            if (cur_packet->incp_head.type == INCP_DATA) // data，接受窗口只处理数据
            {
                int windows_id = cur_packet->incp_head.seq_num % (2 * MAX_WND_SIZE);
                if (cur_packet->incp_head.seq_num < cur_recv_state.ack_until + 2 * MAX_WND_SIZE)
                { // 每个加入窗口的data包 都返回ack
                    respond_ack(cur_packet);
                    if (cur_packet->incp_head.seq_num > cur_recv_state.ack_until)
                    {
                        std::cout << "recv one data packet: " << cur_packet->incp_head.seq_num << " len:" << cur_packet->ip_head.length << std::endl;
                        cur_recv_state.recv_window[windows_id] = *cur_packet;
                        // 更新cur_recv_state.ack_until,累计确认
                        while (cur_recv_state.recv_window[windows_id].incp_head.seq_num == cur_recv_state.ack_until + 1)
                        { // 必须一次写入如果不够等待可以一次写入。
                            int len = cur_recv_state.recv_window[windows_id].incp_head.length - sizeof(incp_header_t);
                            for (int i = 0; i < len;)
                            {
                                i += cur_recv_state.buff.Write(cur_recv_state.recv_window[windows_id].data + i, len - i);
                            }
                            cur_recv_state.ack_until += 1;
                            windows_id = (windows_id + 1) % (2 * MAX_WND_SIZE);
                        }
                    }
                }
            }
            else if (cur_packet->incp_head.type == INCP_ACK) // ack 更新发送窗口 ，如果任务完成通知另一方
            {
                // TODO 确定是此时send_state所对应的任务
                std::cout << "recv one ack packet: " << cur_packet->incp_head.ack_num << std::endl;
                // std::lock_guard<std::mutex> lk(ackwin_lock);
                if ((int)send_state.current_task.socket != socket)
                {
                    std::cout << "this ack packet don't belong to thecurrent send task\n";
                }
                else // if (send_state.last_acked<cur_packet->incp_head.ack_num && cur_packet->incp_head.ack_num <= send_state.last_sent)
                {
                    std::cout << "recv success ack\n";
                    send_state.ack_window[cur_packet->incp_head.ack_num % (2 * MAX_WND_SIZE)] = true;
                }
                /*else
                {
                    std::cout << "this is a last ack packet now acked:" << send_state.last_acked << " now last send:" << send_state.last_sent<<'\n';
                }*/
            }
        }
        else
        {
            std::cout << "bad packet\n";
            std::cout << cur_packet->data << '\n';
            abort();
        }
        return cur_packet->ip_head.length;
    }
    pcap_t *open_pcap(const char *dev_name)
    { // 打开自己的网卡接口
        char errBuf[PCAP_ERRBUF_SIZE];
        pcap_t *device = pcap_create(dev_name, errBuf);
        if (device == NULL)
        {
            std::cout << errBuf << std::endl;
        }

        int ret = pcap_activate(device);
        if (ret != 0)
        {
            std::cout << pcap_geterr(device) << std::endl;
        }
        else
            std::cout << "success open pcap\n";
        return device;
    }
    uint16_t crc16_for_byte(uint16_t r)
    {
        for (int j = 0; j < 8; ++j)
            r = (r & 1 ? 0 : (uint16_t)0xEDB88320L) ^ r >> 1;
        return r ^ (uint16_t)0xFF000000L;
    }

    void crc16(const void *data, size_t n_bytes, uint16_t *crc)
    {
        static uint16_t table[0x100];
        if (!*table)
            for (size_t i = 0; i < 0x100; ++i)
                table[i] = crc16_for_byte(i);
        for (size_t i = 0; i < n_bytes; ++i)
            *crc = table[(uint8_t)*crc ^ ((uint8_t *)data)[i]] ^ *crc >> 8;
    }

    uint16_t compute_checksum(const void *pkt, size_t n_bytes)
    {
        uint16_t crc = 0;
        crc16(pkt, n_bytes, &crc);
        return crc;
    }
};