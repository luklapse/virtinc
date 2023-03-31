#include "net.h"
#include <iostream>
#include <cstring>
#include <assert.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>
// 假设一对一传输
// 主机只有一个网口，switch对应主机有若干端口
pcap_t *device;
// 跟着cur_task更新
_send_state send_state;
std::queue<task> task_queue;
std::mutex task_lock;
std::condition_variable task_con;

std::mutex ackwin_lock;
// 作为接受端才会使用，接受ack报文不使用
_recv_state recv_state[MAX_CON_NUM];

_conn_t conn_t[MAX_CON_NUM];
std::map<_conn_t, int> socket_map; //_conn_t -> socket

char send_buff[MAXBUFF] = {0};
int end = 0;
int begin = 0;
int init_conn(uint32_t conn_id, uint32_t src_ip, uint32_t dst_ip);
int send(int socket, void *addr, unsigned int size);

int recv(int socket, void *addr, unsigned int size);

void close_conn(int socket);

void *copy_send_buff(void *addr, unsigned int size);

void run_send();
void run_recv();

void send_encode_packet(task *current_task, int seq);

int recv_pack(ip_packet *cur_packet);
void respond_ack(ip_packet *cur_packet);
void recv_handle(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void get_device(char *name_other);