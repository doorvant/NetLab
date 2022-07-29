#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // 复制请求包数据
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    // 修改报头，填写校验和
    icmp_hdr_t* hdr = (icmp_hdr_t*)txbuf.data;
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t*)txbuf.data, txbuf.len);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // 报头检测
    if (buf->len < sizeof(icmp_hdr_t)) return;

    // 判断是否为回显
    icmp_hdr_t* hdr = (icmp_hdr_t*)buf->data;
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // 若是，调用icmp_resp()回送一个回显应答
        icmp_resp(buf, src_ip);
    }
    return;
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    buf_init(&txbuf, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);

    icmp_hdr_t* icmp_h = (icmp_hdr_t*)txbuf.data;

    ip_hdr_t* ip_h = (ip_hdr_t*)(txbuf.data + sizeof(icmp_hdr_t));
    ip_hdr_t* hdr = (ip_hdr_t*)(recv_buf->data);

    int8_t* icmp_data = (int8_t*)(txbuf.data + sizeof(icmp_hdr_t) + sizeof(ip_hdr_t));
    int8_t* ip_data = (int8_t*)(recv_buf->data + sizeof(ip_hdr_t));

    icmp_h->type = ICMP_TYPE_UNREACH;
    icmp_h->code = code;
    icmp_h->id16 = 0;
    icmp_h->seq16 = 0;
    
    memcpy(ip_h, hdr, sizeof(ip_hdr_t));
    memcpy(icmp_data, ip_data, 8);

    icmp_h->checksum16 = 0;
    icmp_h->checksum16 = checksum16((uint16_t*)txbuf.data, txbuf.len);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}