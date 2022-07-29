#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

int id = 0;

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    if (buf->len < sizeof(ip_hdr_t)) return;

    ip_hdr_t* pkt = (ip_hdr_t*) buf->data;
    if (pkt->version != IP_VERSION_4) return;
    if (swap16(pkt->total_len16) > buf->len)  return;

    uint16_t checksum = pkt->hdr_checksum16;
    pkt->hdr_checksum16 = 0;

    if (checksum != checksum16((uint16_t*)pkt, sizeof(ip_hdr_t))) return;
    pkt->hdr_checksum16 = checksum;

    if (strncmp((char*)pkt->dst_ip, (char*)net_if_ip, NET_IP_LEN) != 0) return;

    if (buf->len > swap16(pkt->total_len16)) {
        buf_remove_padding(buf, swap16(pkt->total_len16)-buf->len);
    }

    if (pkt->protocol != NET_PROTOCOL_ICMP &&
        // pkt->protocol != NET_PROTOCOL_TCP  &&
        pkt->protocol != NET_PROTOCOL_UDP) {
        icmp_unreachable(buf, pkt->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }
    buf_remove_header(buf, sizeof(ip_hdr_t));
    net_in(buf, pkt->protocol, pkt->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // 添加IP数据报头部
    buf_add_header(buf, sizeof(ip_hdr_t));
    
    // 填写IP数据报头部字段
    ip_hdr_t* hdr         = (ip_hdr_t*)buf->data;
    hdr->hdr_len          = 5;
    hdr->version          = IP_VERSION_4;
    hdr->tos              = 0;
    hdr->total_len16      = swap16((uint16_t)buf->len); 
    hdr->id16             = swap16((uint16_t)id);
    hdr->flags_fragment16 = swap16(mf + offset);
    hdr->ttl              = 64;
    hdr->protocol         = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);  
    hdr->hdr_checksum16   = 0;
    hdr->hdr_checksum16   = checksum16((uint16_t*)hdr, sizeof(ip_hdr_t));

    // 发送封装后的IP头部和数据
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    int ip_max_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    uint8_t* ptr = buf->data;
    size_t buf_len = buf->len;
    buf_t* ip_buf = (buf_t*)malloc(sizeof(buf_t));
    uint16_t offset = 0;

    while(buf_len > ip_max_len) {
        buf_init(ip_buf, ip_max_len);
        memcpy(ip_buf->data, ptr, ip_max_len);
        ip_fragment_out(ip_buf, ip, protocol, id, offset/8, IP_MORE_FRAGMENT);
        ptr += ip_max_len;
        buf_len -= ip_max_len;
        offset += ip_max_len;
    }
    buf_init(ip_buf, buf_len);
    memcpy(ip_buf->data, ptr, buf_len);
    ip_fragment_out(ip_buf, ip, protocol, id, offset/8, 0);
    id++;
    return;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}