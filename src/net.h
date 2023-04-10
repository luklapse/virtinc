#pragma once
#ifndef _NET_H_
#define _NET_H_
#include <stdint.h>
#include <iostream>
#include <pcap/pcap.h>
#include "buff.h"
#include "safequeue.h"

#define MTU 1500                      // 数据帧最大字节
#define MSS MTU - sizeof(ip_header_t) // 避免ip分片，实际这个数据是由三次握手确定

#define INCP_DATA 0
#define INCP_ACK 1

#define MAX_WND_SIZE 512

#define MAX_BUFFSIZE 1 << 20
// 0 ~ MAX_CON_NUM-1 代表了套字节
#define MAX_CON_NUM 100
/*******************************************************************************
 * put all data structures and function prototypes here in this file
 ******************************************************************************/

/*******************************************************************************
 * data structures about packet headers, ip_header and layer-4 header
 ******************************************************************************/

typedef struct __attribute__((packed)) IP_Header
{
    uint8_t version : 4, headlen : 4; // 版本信息(前4位)，头长度(后4位)
    uint8_t type_of_service;          // 服务类型
    uint16_t length;                  // 整个ip数据包长度
    uint16_t packet_id;               // 数据包标识
    uint16_t slice_info;              // 分片信息  x DF MF DF代表分片
    uint8_t ttl;                      // 存活时间
    uint8_t type_of_protocol;         // 协议类型
    uint16_t checksum;                // 校验和
    uint32_t src_ip;                  // 源ip
    uint32_t dst_ip;                  // 目的ip
} ip_header_t;                        // 总长度20Bytes

typedef struct __attribute__((packed)) INCP_Header
{
    uint8_t type;    // INCP_DATA：0；INCP_ACK：1
    uint16_t length; // 整个incp数据包长度
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t window_size;
    uint32_t conn_num; // 选取方式自己闲置的套字节

    uint8_t pad[3]; // 填充
} incp_header_t;    // 总长度16Bytes

/*#define DATA_SIZE MSS-sizeof(incp_header_t)
struct incp_packet
{ // 构建一个incp_packet包,协议的构建层
    incp_header_t incp_head;
    char data[DATA_SIZE];
    incp_packet();
    void set_incp_packet(incp_header_t &other, void *other_body); // 初始化包
};*/
struct ip_packet
{
    ip_header_t ip_head;
    incp_header_t incp_head;
    char data[MSS];
    ip_packet()
    {
        memset(&ip_head, 0, sizeof(ip_packet));
        memset(&incp_head, 0, sizeof(incp_head));
        memset(data, 0, sizeof(data));
    };
    void operator=(ip_packet &other)
    {
        memcpy(this, &other, sizeof(ip_packet));
    }
    // void set_ip_packet(ip_header_t &other_ip_head, incp_header_t &other_incp_head, void *other_body);
};
/*******************************************************************************
 * states and methods of switches
 ******************************************************************************/

struct _task
{
    int socket; // 该任务所代表的连接，也代表是一次完整的数据，我们需要把这个数据分包发送
    int size;   // 代表需要从send_buff读取的大小

    _task() {}
    _task(const _task &it)
    {
        socket = it.socket;
        size = it.size;
    }
    _task(int id, int size_other)
    {
        socket = id;
        size = size_other;
    }
};

struct _conn_t
{
    uint32_t conn_id; // 类似于端口，由连接两方共同规定
    //-1 代表没有连接
    // 0 代表准备接受连接
    // 1~MAX_CON 代表已经建立连接
    uint32_t src_ip;
    uint32_t dst_ip;
    _conn_t()
    {
        conn_id = src_ip = dst_ip = -1;
    }
    _conn_t(uint32_t a, uint32_t b, uint32_t c)
    {
        conn_id = a;
        src_ip = b;
        dst_ip = c;
    }
    _conn_t(const _conn_t &it)
    {
        conn_id = it.conn_id;
        src_ip = it.src_ip;
        dst_ip = it.dst_ip;
    }
    _conn_t(_conn_t &&it)
    {
        conn_id = it.conn_id;
        src_ip = it.src_ip;
        dst_ip = it.dst_ip;
    }
    bool operator<(const _conn_t &it) const
    {
        if (src_ip == it.src_ip)
        {
            if (dst_ip == it.dst_ip)
            {
                return conn_id < it.dst_ip;
            }
            return dst_ip < it.dst_ip;
        }
        return src_ip < it.src_ip;
    }
};

struct _send_state
{
    ip_packet send_window[MAX_WND_SIZE * 2];
    bool ack_window[MAX_WND_SIZE * 2];

    CircularBuffer buff;

    int last_sent;
    int last_acked; // 上次确认过ack的发送窗口

    ThreadSafeQueue<_task> tasks;

    int last_seq_of_current_task;
    struct _task *current_task;

    _send_state() : buff(MAX_BUFFSIZE)
    {
        memset(ack_window, 0, sizeof(ack_window));
        last_sent = 0; // seq从1开始
        last_acked = 0;

        last_seq_of_current_task = -2;
        current_task = nullptr;
    }
};

struct _recv_state // TODO ack_window也算到recv_window里
{
    ip_packet recv_window[MAX_WND_SIZE * 2];
    int ack_until; // 上一次累计确认的位置，收取data设置

    CircularBuffer buff;

    _recv_state() : buff(MAX_BUFFSIZE / 10)
    {
        ack_until = -1;
    }
    void close()
    {
        ack_until = -2;
    }
    void reset()
    {
        ack_until = -1;
    }
};
/* 每个socket对应的结构
struct _socket
{
    _recv_state recv_state;
    _conn_t conn_t;
};
*/
#endif
