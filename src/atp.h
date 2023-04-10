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
        //recv_thread = std::thread(&ATP::run_recv, this);
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
            if (conn_t[i].conn_id == -1)
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
        else if (conn_id = 0) //准备接受这个地址信息
        {
            for (int i = 1; i <=MAX_CON_NUM; i++)
            {
                if (conn_t[i].conn_id == -1)
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

    int send(int socket, char *addr, unsigned int size)
    { // 阻塞的端口设计。
        int ans = 0;
        while (ans < size)
        { // 对很大发送数据分割为多次发送任务。
            ans += send_state.buff.Write(addr + ans, size - ans);
            std::cout<<"send task emplace"<<std::endl;
            send_state.tasks.emplace(socket, size);
        }
        return size;
    }

    int recv(int socket, char *addr, unsigned int size)
    { // 构建recv_state
        // TODO 阻塞接口等待接受到信息，接受到足够的信息，除非断开连接
        int ans = 0;
        while (ans < size)
        {
            ans += recv_state[socket].buff.Read(addr, size);
        }
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
    _conn_t conn_t[MAX_CON_NUM+1];
    // conn_t->socket，内部是安全的，但对接口不是线程安全的
    std::map<_conn_t, int> socket_map;
    void run_send()
    {
        std::cout << "run send thread\n";
        // 这里开启一个线程专门用于处理task队列，并且通过线程间通信得到成功返回
        if (send_state.current_task==nullptr)
        {
            send_state.tasks.wait_and_pop(*send_state.current_task);
            std::cout<<"ini cur_task "<<send_state.current_task->size<<send_state.current_task->socket<<std::endl;
        }
        while (true)
        {
            std::cout << "cur_task....\n";
            _task *cur_task = send_state.current_task;
            int seq = send_state.last_acked + 1;
            // 超时重传的数据,加入缓冲区
            for (; seq <= send_state.last_sent; seq++)
            { // TODO 需要时间戳的问题 即选择重发没有acked且超时报文
                auto tmp_window = seq % (2 * MAX_WND_SIZE);
                pcap_inject(device, &send_state.send_window[tmp_window], send_state.send_window[tmp_window].ip_head.length);
            }
            // 下一步发送的数据
            send_encode_packet(cur_task, seq);
            // 等待回应的ack，更新last_acked
            // sleep(0.5); 2TT;
            {
                std::lock_guard<std::mutex> lk(ackwin_lock);
                for (int i = 0; i < 2 * MAX_WND_SIZE && send_state.ack_window[(send_state.last_acked + 1) % (2 * MAX_WND_SIZE)]; i++)
                {
                    send_state.ack_window[(send_state.last_acked + 1) % (2 * MAX_WND_SIZE)] = false;
                    send_state.last_acked++;
                }
            }
            if (send_state.last_acked == send_state.last_seq_of_current_task)
            {
                send_state.tasks.wait_and_pop(*send_state.current_task);
            }
        }
    }
    void send_encode_packet(_task *cur_task, int seq)
    {
        for (; cur_task->size > 0 && seq <= send_state.last_acked + MAX_WND_SIZE * 2; seq++)
        {
            // 装包
            auto tmp_window = seq % (2 * MAX_WND_SIZE);

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
                send_state.last_seq_of_current_task = seq;
                cur_task->size = 0;
            }
            incp_head.seq_num = seq;
            incp_head.window_size; // 告知自己的接受缓冲区
            incp_head.conn_num = conn_t[cur_task->socket].conn_id;

            ip_header_t &ip_head = send_state.send_window[tmp_window].ip_head;
            ip_head.version = 0;
            ip_head.length = incp_head.length + sizeof(ip_head);
            ip_head.src_ip = conn_t[cur_task->socket].src_ip;
            ip_head.dst_ip = conn_t[cur_task->socket].dst_ip;
            ip_head.ttl = 0x0f;
            ip_head.checksum = 0;
            // 由于send接口写入缓冲区的，正常情况一定存在相应的数据
            if (send_state.buff.Read(send_state.send_window[tmp_window].data, incp_head.length - sizeof(incp_header_t)) != incp_head.length - sizeof(incp_header_t))
            {
                std::cout << "send_buff read error\n";
            }
            // 计算校验码
            ip_head.checksum = compute_checksum(&send_state.send_window[tmp_window], ip_head.length);
            // 发送
            pcap_inject(device, &send_state.send_window[tmp_window], send_state.send_window[tmp_window].ip_head.length);
        }
        // TODO 更新send_state状态
        send_state.last_sent = seq - 1;
    }

    void recv_handle(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
    {
        // 接受的数据到缓冲区
        printf("Received Packet Size: %d\n", pkthdr->len);
        printf("Payload:\n");
        std::cout << packet << '\n';
        // 默认为整数个ip片，解析ip片
        recv_pack((ip_packet *)packet);
        return;
    }
    // 打包到滑动窗口发送
    void run_recv()
    {
        std::cout << "run recv thread\n";
        std::function<void(u_char *, const struct pcap_pkthdr *, const u_char *)> callback_tmp =
            std::bind(&ATP::recv_handle, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        pcap_loop(device, -1, *callback_tmp.target<pcap_handler>(), nullptr);
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
    }
    int recv_pack(ip_packet *cur_packet)
    {
        // 处理单个ip_packet包 读入到接受窗口,处理data
        std::cout<<"recv one packet\n";
        if (compute_checksum(cur_packet, cur_packet->ip_head.length) == cur_packet->ip_head.checksum)
        { // 查找对应连接
            int socket;
            auto ans = socket_map.find(_conn_t(cur_packet->incp_head.conn_num, cur_packet->ip_head.dst_ip, cur_packet->ip_head.src_ip));
            if (ans != socket_map.end())
                socket = ans->second;
            else
            { // 接受连接
                socket = accept_conn(cur_packet->incp_head.conn_num, cur_packet->ip_head.dst_ip, cur_packet->ip_head.src_ip);
                std::cout << "don't establish a connect\n";
                if(socket==-1) return 0; // 丢弃这个包
            }
            _recv_state &cur_recv_state = recv_state[socket];

            if (cur_packet->incp_head.type == 0) // data，接受窗口只处理数据
            {
                int windows_id = cur_packet->incp_head.seq_num % (2 * MAX_WND_SIZE);
                if (cur_packet->incp_head.seq_num < cur_recv_state.ack_until + 2 * MAX_WND_SIZE)
                { // 每个加入窗口的data包 都返回ack
                    cur_recv_state.recv_window[windows_id] = *cur_packet;
                    respond_ack(cur_packet);
                    // 更新cur_recv_state.ack_until
                    while (cur_recv_state.recv_window[windows_id].incp_head.seq_num == cur_recv_state.ack_until + 1)
                    {
                        if (cur_recv_state.buff.Write(cur_recv_state.recv_window[windows_id].data, cur_recv_state.recv_window[windows_id].incp_head.length - sizeof(incp_header_t), 1) == 0)
                            break;
                        cur_recv_state.ack_until += 1;
                        windows_id = (windows_id + 1) % (2 * MAX_WND_SIZE);
                    }
                }
            }
            else if (cur_packet->incp_head.type == 1) // ack 更新发送窗口 ，如果任务完成通知另一方
            {
                // TODO 确定是此时send_state所对应的任务
                std::lock_guard<std::mutex> lk(ackwin_lock);
                if (send_state.current_task->socket != socket)
                {
                    std::cout << "this ack packet don't belong to thecurrent send task\n";
                }
                else
                    send_state.ack_window[cur_packet->incp_head.ack_num % (2 * MAX_WND_SIZE)] = true;
            }
        }
        else
        {
            std::cout << "bad packet\n";
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
        else std::cout<<"success open pcap\n";
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