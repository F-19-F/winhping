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
	//p以字节为单位
	uint8_t* p = (uint8_t*)packet;
	uint32_t sum = 0;
	uint16_t csum = 0;
	//16位为一组取反后求和,即2个字节为一组,共10组,默认IP头部大小为20字节
	uint16_t group = 0;
	while (len > 1)
	{
		//高位
		group = (*p) << 8;
		p++;
		//低位
		group |= (*p);
		p++;
		len -= 2;
		sum += group;
	}
	if (len)
	{
		sum += (*p) << 8;
	}
	//如果sum有进位
	while (sum >> 16)
	{
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	csum = ~(uint16_t)sum;
	return csum;
}
// 计算网络中（大端）的前缀长度
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