#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // 该函数用于处理接收到的以太网数据帧
    // 判断数据长度，若小于以太网帧头部，则丢弃不处理；
    if (buf->len < sizeof(ether_hdr_t)) return;
    // 获取以太网帧头部中的数据，包括源MAC地址以及协议/长度信息
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    uint8_t src[NET_MAC_LEN];
    net_protocol_t protocol = swap16(hdr->protocol16);
    memcpy(src, hdr->src, NET_MAC_LEN);
    // 移除以太网数据帧头部
    buf_remove_header(buf, sizeof(ether_hdr_t));
    // 向协议栈的上层传递数据包
    net_in(buf, protocol, src);
    return;
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // 该函数用于发送以太网数据帧
    // 判断数据长度，若小于以太网最低负载长度，则进行填充
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT-(buf->len));
    }
    // 添加以太网头部
    buf_add_header(buf, sizeof(ether_hdr_t));
    // 对以太网头部进行操作
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    // 将源MAC地址设置为本机MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    // 设置目标MAC地址
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    // 设置协议/长度信息
    hdr->protocol16 = swap16(protocol);
    // 使用网卡将以太网数据帧发送出去
    driver_send(buf);
    return;
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
