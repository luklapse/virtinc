#include <iostream>
#include <algorithm>
#include <cstring>
#include <pcap/pcap.h>

#include "net.h"
/*incp_packet::incp_packet(){
    memset(&incp_head,0,sizeof(incp_head));
    memset(data,0,sizeof(data));
}
void incp_packet::set_incp_packet(incp_header_t &other, void *other_body)
{
    incp_head = other; // 浅copy
    memset(data, 0, DATA_SIZE);
    memcpy(data, other_body, sizeof(other_body));
    return ;
}*/

ip_packet::ip_packet(){
    memset(&ip_head,0,sizeof(ip_packet));
    memset(&incp_head,0,sizeof(incp_head));
    memset(data,0,sizeof(data));
}
void ip_packet::set_ip_packet(ip_header_t &other_ip_head, incp_header_t & other_incp_head,void * other_body){
    memcpy(&ip_head,&other_ip_head,sizeof(ip_head));
    memcpy(&incp_head,&other_incp_head,sizeof(incp_head));

    memset(data,0,sizeof(data));//或者data[]='\0'
    memcpy(data,other_body,incp_head.length-sizeof(incp_head));
    return;
}
int task::buf_size=0;
pcap_t *open_pcap(char *dev_name)
{ // 打开自己的网卡接口
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *device = pcap_create("switch-iface2", errBuf);
    if (device == NULL)
    {
        std::cout << errBuf << '\n';
    }
    int ret = pcap_activate(device);
    if (ret != 0)
    {
        std::cout << pcap_geterr(device) << '\n';
    }
    return device;
}
uint16_t crc16_for_byte(uint16_t r) {
    for(int j = 0; j < 8; ++j)
        r = (r & 1? 0: (uint16_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint16_t)0xFF000000L;
}

void crc16(const void *data, size_t n_bytes, uint16_t* crc) {
    static uint16_t table[0x100];
    if(!*table)
        for(size_t i = 0; i < 0x100; ++i)
            table[i] = crc16_for_byte(i);
    for(size_t i = 0; i < n_bytes; ++i)
        *crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

uint16_t compute_checksum(const void* pkt, size_t n_bytes) {
    uint16_t crc = 0;
    crc16(pkt, n_bytes, &crc);
    return crc;
}
