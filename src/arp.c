#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // 该函数用于发送arp请求来获取目标IP的MAC地址
    // 初始化ARP报头
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    
    // 填写ARP报头相关信息
    pkt->hw_type16  = swap16(ARP_HW_ETHER); 
    pkt->pro_type16 = swap16(NET_PROTOCOL_IP); 
    pkt->hw_len     = NET_MAC_LEN;
    pkt->pro_len    = NET_IP_LEN;
    pkt->opcode16   = swap16(ARP_REQUEST);
    
    // 源MAC地址设置为本机MAC地址，目标MAC地址设置为全0
    for (int i = 0; i < NET_MAC_LEN; i++) {
        pkt->sender_mac[i] = net_if_mac[i];
        pkt->target_mac[i] = 0x00;
    }

    // 源IP地址设置为本机IP地址，目标IP地址设置为target_ip
    for (int i = 0; i < NET_IP_LEN; i++) {
        pkt->sender_ip[i] = net_if_ip[i];
        pkt->target_ip[i] = target_ip[i];
    }
    // 调用ethernet_out()生成并发送以太网数据帧
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
    return;
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // 该函数用于向目标主机发送一个ARP响应包
    // 初始化ARP报头
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    // 填写ARP报头相关信息
    pkt->hw_type16  = swap16(ARP_HW_ETHER); 
    pkt->pro_type16 = swap16(NET_PROTOCOL_IP); 
    pkt->hw_len     = NET_MAC_LEN;
    pkt->pro_len    = NET_IP_LEN;
    pkt->opcode16   = swap16(ARP_REPLY);
    // 源MAC地址设置为本机MAC地址，目标MAC地址设置为target_mac
    for (int i = 0; i < NET_MAC_LEN; i++) {
        pkt->sender_mac[i] = net_if_mac[i];
        pkt->target_mac[i] = target_mac[i];
    }
    // 源IP地址设置为本机IP地址，目标IP地址设置为target_ip
    for (int i = 0; i < NET_IP_LEN; i++) {
        pkt->sender_ip[i] = net_if_ip[i];
        pkt->target_ip[i] = target_ip[i];
    }
    // 调用ethernet_out()生成并发送以太网数据帧
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
    return;
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // 该函数用于处理一个收到的ARP数据包
    // 判断数据长度，若小于ARP头部则丢弃
    if (buf->len < sizeof(arp_pkt_t)) return;

    // 获取ARP头部信息并进行报头检查
    arp_pkt_t *pkt = (arp_pkt_t *)buf->data;   
    if (pkt->hw_type16  != swap16(ARP_HW_ETHER))    return; 
    if (pkt->pro_type16 != swap16(NET_PROTOCOL_IP)) return; 
    if (pkt->hw_len     != NET_MAC_LEN)             return;
    if (pkt->pro_len    != NET_IP_LEN)              return;
    if (pkt->opcode16   != swap16(ARP_REQUEST) && 
        pkt->opcode16   != swap16(ARP_REPLY))       return;

    // 根据源IP地址和源MAC地址更新arp_table
    map_set(&arp_table, pkt->sender_ip, pkt->sender_mac);

    // 查看arp_buf中是否有对应待发送的数据包
    buf_t *last_buf = map_get(&arp_buf, pkt->sender_ip);
    if (last_buf) {
        // 若有待发送的数据包，调用ethernet_out()进行发送
        ethernet_out(last_buf, pkt->sender_mac, NET_PROTOCOL_IP);
        // 将已发送的数据包从arp_buf中删除
        map_delete(&arp_buf, pkt->sender_ip);
    } else {
        // 若无待发送数据包，判断该数据包是否为ARP_REQUEST且目标IP是否为本机IP
        if (pkt->opcode16 == swap16(ARP_REQUEST) &&
            strncmp((char*)pkt->target_ip, (char*)net_if_ip, NET_IP_LEN) == 0) {
            // 若满足判断条件，则调用arp_resp()发送一个响应包
            arp_resp(pkt->sender_ip, pkt->sender_mac);
        }
    }

    return;
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // 该函数用于处理一个需要发送的数据包
    // 在arp_table中查找目标IP地址对应的MAC地址
    uint8_t* mac = map_get(&arp_table, ip);

    if (mac) {
        // arp_table中有对应的MAC地址
        // 调用ethernet_out()生成并发送以太网数据帧
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // arp_table中没有对应的MAC地址
        // 若arp_buf中该IP有对应数据包，则说明正在等待该IP回应arp请求
        if (map_get(&arp_buf, ip) == NULL) {
            // arp_buf中该IP没有对应数据包
            // 将当前数据包存入arp_buf
            map_set(&arp_buf, ip, buf);
            // 调用arp_req()获取目标IP地址的MAC地址
            arp_req(ip);
        }
    }
    return;
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}