#pragma once
#include <stdio.h>
#include <string>
#include <vector>
struct iface_info {
	unsigned long ifIndex;//接口索引
	std::string name;//接口名称(Device\NPF_{*})
	std::string description;//字符串描述
	uint8_t mac[6];//mac地址
	uint8_t ip[4];//ipv4地址
	uint8_t prefixlen;//掩码
	uint8_t gateway[4];//网关
};
std::string unicode_to_str(wchar_t* unistr);
std::vector<iface_info> find_ifaces();