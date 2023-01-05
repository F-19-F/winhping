#pragma once
#include <stdio.h>
#include <string>
#include <vector>
struct iface_info {
	unsigned long ifIndex;//�ӿ�����
	std::string name;//�ӿ�����(Device\NPF_{*})
	std::string description;//�ַ�������
	uint8_t mac[6];//mac��ַ
	uint8_t ip[4];//ipv4��ַ
	uint8_t prefixlen;//����
	uint8_t gateway[4];//����
};
std::string unicode_to_str(wchar_t* unistr);
std::vector<iface_info> find_ifaces();