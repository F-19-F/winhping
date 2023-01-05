#include <stdint.h>
#include "_internet.h"
namespace EthType
{
	const uint16_t ARP = 0x0806;
	const uint16_t IPv4 = 0x0800;
}namespace IpProto
{
	const uint8_t ICMP = 0x01;
}
uint16_t CheckSum(uint8_t* packet, int len)
{
	//p���ֽ�Ϊ��λ
	uint8_t* p = (uint8_t*)packet;
	uint32_t sum = 0;
	uint16_t csum = 0;
	//16λΪһ��ȡ�������,��2���ֽ�Ϊһ��,��10��,Ĭ��IPͷ����СΪ20�ֽ�
	uint16_t group = 0;
	while (len > 1)
	{
		//��λ
		group = (*p) << 8;
		p++;
		//��λ
		group |= (*p);
		p++;
		len -= 2;
		sum += group;
	}
	if (len)
	{
		sum += (*p) << 8;
	}
	//���sum�н�λ
	while (sum >> 16)
	{
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	csum = ~(uint16_t)sum;
	return csum;
}
// ���������У���ˣ���ǰ׺����
int GetMaskLen(uint8_t* mask, int len)
{
	int sum = 0;
	int loop8 = 0;
	for (int i = 0; i < len; i++)
	{
		loop8 = 0;
		while (loop8 < 8)
		{
			if ((*(mask) >> (7 - loop8)) & 1)
			{
				sum++;
			}
			else
			{
				break;
			}
			loop8++;
		}
		mask++;
	}
	return sum;
}