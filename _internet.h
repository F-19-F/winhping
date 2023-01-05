#pragma once
#include <stdio.h>
typedef struct EthHeader {
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t ethertype;
} EthHeader;
//以太网类型
namespace EthType
{
	extern const uint16_t ARP;
	extern const uint16_t IPv4;
}
//IP上层协议
namespace IpProto
{
	extern const uint8_t ICMP;
}
//IP头部
struct IpHeader {
#ifdef CPuIS_BIG_ENDIAN
	uint8_t version : 4;//ip版本-4位
	uint8_t hdrlen : 4;//首部长度-4位
	uint8_t tos;//区分服务,一般不使用
	uint16_t len;//网络层及以上层数据包总长度
	uint16_t id;//标识位
	uint16_t flag_offset;//标志位及偏移
	uint8_t ttl;//生存时间
	uint8_t proto;//协议
	uint16_t csum;//首部检验和
	uint8_t src[4];//源地址
	uint8_t dest[4];//目的地址
#else
	uint8_t hdrlen : 4;//首部长度-4位
	uint8_t version : 4;//ip版本-4位
	uint8_t tos;//区分服务,一般不使用
	uint16_t len;//网络层及以上层数据包总长度
	uint16_t id;//标识位
	uint16_t flag_offset;//标志位及偏移
	uint8_t ttl;//生存时间
	uint8_t proto;//协议
	uint16_t csum;//首部检验和
	uint8_t src[4];//源地址
	uint8_t dest[4];//目的地址
#endif

};
// ICMP头部
struct IcmpHeader {
	uint8_t type;//类型
	uint8_t code;//代码
	uint16_t csum;//检验和
	uint32_t roh;//首部剩余部分
};
struct icmp_ra_addr
{
	uint32_t ira_addr;
	uint32_t ira_preference;
};


struct icmp
{
	uint8_t  icmp_type;	/* type of message, see below */
	uint8_t  icmp_code;	/* type sub code */
	uint16_t icmp_cksum;	/* ones complement checksum of struct */
	union
	{
		uint8_t ih_pptr;		/* ICMP_PARAMPROB */
		//struct in_addr ih_gwaddr;	/* gateway address */
		struct ih_idseq		/* echo datagram */
		{
			uint16_t icd_id;
			uint16_t icd_seq;
		} ih_idseq;
		uint32_t ih_void;

		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct ih_pmtu
		{
			uint16_t ipm_void;
			uint16_t ipm_nextmtu;
		} ih_pmtu;

		struct ih_rtradv
		{
			uint8_t irt_num_addrs;
			uint8_t irt_wpa;
			uint16_t irt_lifetime;
		} ih_rtradv;
	} icmp_hun; // header union 头部部分联合体
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
	union
	{
		struct
		{
			uint32_t its_otime;
			uint32_t its_rtime;
			uint32_t its_ttime;
		} id_ts;
		struct icmp_ra_addr id_radv;
		uint32_t   id_mask;
		uint8_t    id_data[1];
	} icmp_dun; // data union 数据部分联合体
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};
//首部校验和算法
uint16_t CheckSum(uint8_t* packet, int len);
//计算子网前缀长度
int GetMaskLen(uint8_t* mask, int len);