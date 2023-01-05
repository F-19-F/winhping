#pragma once
#include "rwutil.h"
bool arp_request(const iface_info& iface, const uint8_t ip[4], uint8_t mac[6]);
int dns_request4(const char* domain, uint32_t* ip);