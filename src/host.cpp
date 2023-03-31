#include "host.h"

void get_device(char *name_other)
{
    device = open_pcap(name_other);
}
// 接口
int init_conn(uint32_t conn_id,uint32_t src_ip,uint32_t dst_ip)//conn_id由发送方确定
{
    for (int i = 0; i < MAX_CON_NUM; i++)
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

// 维护一个双向的缓冲区,返回开始地址，且内容时连续的地址

int send(int socket, void *addr, unsigned int size)
{ // 返回copy到缓冲区的字节数
    if (size > MAXBUFF)
        return -2; // 代表超过缓冲区大小
    addr = copy_send_buff(addr, size);
    while (addr == nullptr)
    {
        addr = copy_send_buff(addr, size);
    }
    {
        std::lock_guard<std::mutex> lock(task_lock);
        task_queue.emplace(socket, addr, size);
        task_con.notify_one();
    }
    // 阻塞的端口设计一个。
    return size;
}

void *copy_send_buff(void *addr, unsigned int size)
{
    void *ret = nullptr;
    if (begin < end)
    {
        if (end + size <= MAXBUFF)
        {
            memcpy(send_buff + end, addr, size);
            ret = send_buff + end;
            end += size;
        }
        else if (end + size > MAXBUFF && size < begin)
        { // 后续空间不够从头部开始
            memcpy(send_buff, addr, size);
            ret = send_buff;
            end = size;
        }
    }
    else // begin>end
    {
        if (end + size < begin)
        {
            memcpy(send_buff + end, addr, size);
            ret = send_buff + end;
            end += size;
        }
    }
    return ret;
}

void run_send()
{
    // 这里开启一个线程专门用于处理task队列，并且通过线程间通信得到成功返回
    while (true)
    {
        task *cur_task = send_state.current_task;
        int seq = send_state.last_acked + 1;
        // 超时重传的数据,加入缓冲区
        for (; seq <= send_state.last_sent; seq++)
        { // TODO 需要时间戳的问题 即选择重发超时报文
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
            std::unique_lock<std::mutex> lock(task_lock);
            task_queue.pop();
            while (task_queue.empty())
            {
                task_con.wait(lock);
            }
            send_state.current_task = &task_queue.front();
        }
    }
}

void send_encode_packet(task *cur_task, int seq)
{
    for (; cur_task->offset <= cur_task->size - 1 && seq <= send_state.last_acked + MAX_WND_SIZE * 2; seq++)
    {
        incp_header_t incp_head;
        incp_head.type = INCP_DATA;
        if (cur_task->offset + MSS <= cur_task->size - 1)
        {
            incp_head.length = MSS + sizeof(incp_header_t);
            cur_task->offset += MSS;
        }
        else
        {
            incp_head.length = cur_task->size - 1 - cur_task->offset + sizeof(incp_header_t);
            cur_task->offset = cur_task->size;
            send_state.last_seq_of_current_task = seq;
        }
        incp_head.seq_num = seq;
        incp_head.window_size; // 告知自己的接受缓冲区
        incp_head.conn_num = conn_t[cur_task->socket].conn_id;

        ip_header_t ip_head;
        ip_head.version = 0;
        ip_head.length = incp_head.length + sizeof(ip_head);
        ip_head.src_ip = conn_t[cur_task->socket].src_ip;
        ip_head.dst_ip = conn_t[cur_task->socket].dst_ip;
        ip_head.ttl = 0x0f;
        ip_head.checksum = 0;
        // 装包
        auto tmp_window = seq % (2 * MAX_WND_SIZE);
        send_state.send_window[tmp_window].set_ip_packet(
            ip_head, incp_head, cur_task->addr + cur_task->offset);

        // 计算校验码
        ip_head.checksum = compute_checksum(&send_state.send_window[tmp_window], ip_head.length);
        // 加入缓冲区
        /*memcpy(send_buff + end, &send_state.send_window[tmp_window], ip_head.length);
        end += ip_head.length;*/
        pcap_inject(device, &send_state.send_window[tmp_window], send_state.send_window[tmp_window].ip_head.length);
    }
    // TODO 更新send_state状态
    send_state.last_sent = seq - 1;
}

int recv(int socket, void *addr, unsigned int size)
{ // 构建recv_state
    // TODO 需要确定接受的是最后一个即 recv_state[conn_id]完成；
    int tmp_size = size < recv_state[socket].size ? size : recv_state[socket].size;
    memcpy(addr, recv_state[socket].addr, tmp_size);
    // 接受数据 发送ack，边接受边回应
    return tmp_size;
}

// 打包到滑动窗口发送
void run_recv()
{
    pcap_loop(device, -1, recv_handle, nullptr);
}
void respond_ack(ip_packet *cur_packet)
{
    incp_header_t incp_head;
    incp_head.type = INCP_ACK;
    incp_head.length = sizeof(incp_head);
    incp_head.ack_num = cur_packet->incp_head.seq_num;
    incp_head.conn_num = cur_packet->incp_head.conn_num;

    ip_header_t ip_head;
    ip_head.version = cur_packet->ip_head.version;
    ip_head.length = incp_head.length + sizeof(ip_head);
    ip_head.src_ip = cur_packet->ip_head.dst_ip;
    ip_head.dst_ip = cur_packet->ip_head.src_ip;
    ip_head.ttl = 0x0f;
    ip_head.checksum = 0;

    ip_packet ack_packet;
    ack_packet.set_ip_packet(ip_head, incp_head, NULL);
    ip_head.checksum = compute_checksum(&ack_packet, ip_head.length);
    pcap_inject(device, &ack_packet, ip_head.length);
}
int recv_pack(ip_packet *cur_packet)
{
    // 处理单个ip_packet包 读入到接受窗口,处理data

    if (compute_checksum(cur_packet, cur_packet->ip_head.length) == cur_packet->ip_head.checksum)
    { // 查找对应连接
        int socket;
        auto ans = socket_map.find(_conn_t(cur_packet->incp_head.conn_num, cur_packet->ip_head.dst_ip, cur_packet->ip_head.src_ip));
        if (ans != socket_map.end())
            socket = ans->second;
        else
        {   
            std::cout << "don't establish a connect\n";
            return 0; // 丢弃这个包
        }
        _recv_state &cur_recv_state = recv_state[socket];

        if (cur_packet->incp_head.type == 0) // data，接受窗口只处理数据
        {
            int windows_id = cur_packet->incp_head.seq_num % (2 * MAX_WND_SIZE);
            if (cur_packet->incp_head.seq_num < cur_recv_state.ack_until + 2 * MAX_WND_SIZE)
            { // 每个加入窗口的data包 都返回ack
                cur_recv_state.recv_window[windows_id].set_ip_packet(
                    cur_packet->ip_head, cur_packet->incp_head, cur_packet->data);
                respond_ack(cur_packet);
                // 更新cur_recv_state.ack_until
                while (cur_recv_state.recv_window[windows_id].incp_head.seq_num == cur_recv_state.ack_until + 1)
                { // TODO 接受缓冲区大小的问题
                    memcpy(cur_recv_state.addr, cur_recv_state.recv_window[windows_id].data, cur_recv_state.recv_window[windows_id].incp_head.length - sizeof(incp_header_t));
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