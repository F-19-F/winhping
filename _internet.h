#pragma once
#include <stdio.h>
typedef struct EthHeader {
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t ethertype;
} EthHeader;
//��̫������
namespace EthType
{
	extern const uint16_t ARP;
	extern const uint16_t IPv4;
}
//IP�ϲ�Э��
namespace IpProto
{
	extern const uint8_t ICMP;
}
//IPͷ��
struct IpHeader {
#ifdef CPuIS_BIG_ENDIAN
	uint8_t version : 4;//ip�汾-4λ
	uint8_t hdrlen : 4;//�ײ�����-4λ
	uint8_t tos;//���ַ���,һ�㲻ʹ��
	uint16_t len;//����㼰���ϲ����ݰ��ܳ���
	uint16_t id;//��ʶλ
	uint16_t flag_offset;//��־λ��ƫ��
	uint8_t ttl;//����ʱ��
	uint8_t proto;//Э��
	uint16_t csum;//�ײ������
	uint8_t src[4];//Դ��ַ
	uint8_t dest[4];//Ŀ�ĵ�ַ
#else
	uint8_t hdrlen : 4;//�ײ�����-4λ
	uint8_t version : 4;//ip�汾-4λ
	uint8_t tos;//���ַ���,һ�㲻ʹ��
	uint16_t len;//����㼰���ϲ����ݰ��ܳ���
	uint16_t id;//��ʶλ
	uint16_t flag_offset;//��־λ��ƫ��
	uint8_t ttl;//����ʱ��
	uint8_t proto;//Э��
	uint16_t csum;//�ײ������
	uint8_t src[4];//Դ��ַ
	uint8_t dest[4];//Ŀ�ĵ�ַ
#endif

};
// ICMPͷ��
struct IcmpHeader {
	uint8_t type;//����
	uint8_t code;//����
	uint16_t csum;//�����
	uint32_t roh;//�ײ�ʣ�ಿ��
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
	} icmp_hun; // header union ͷ������������
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
	} icmp_dun; // data union ���ݲ���������
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};
//�ײ�У����㷨
uint16_t CheckSum(uint8_t* packet, int len);
//��������ǰ׺����
int GetMaskLen(uint8_t* mask, int len);