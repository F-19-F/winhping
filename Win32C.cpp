#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "rwutil.h"
#include <WinSock2.h>
#include <netioapi.h>
// ½âÎömacµØÖ·
bool arp_request(const iface_info& iface, const uint8_t ip[4], uint8_t mac[6]) {
	SOCKADDR_INET srcif;
	srcif.Ipv4.sin_family = AF_INET;
	memcpy(&srcif.Ipv4.sin_addr, iface.ip, 4);

	MIB_IPNET_ROW2 row = { 0 };
	row.InterfaceIndex = iface.ifIndex;
	row.Address.Ipv4.sin_family = AF_INET;
	memcpy(&row.Address.Ipv4.sin_addr, ip, 4);

	if (ResolveIpNetEntry2(&row, &srcif) != NO_ERROR) {
		return false;
	}
	if (row.State == NlnsReachable) {
		memcpy(mac, row.PhysicalAddress, 6);
		return true;
	}
	return false;
}
int dns_request4(const char* domain,uint32_t * ip)
{
	WSADATA wsaData;
	struct in_addr addr;
	auto iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}
	auto remoteHost = gethostbyname(domain);
	if (remoteHost == NULL) {
		auto dwError = WSAGetLastError();
		if (dwError != 0) {
			if (dwError == WSAHOST_NOT_FOUND) {
				//printf("Host not found\n");
				return 2;
			}
			else if (dwError == WSANO_DATA) {
				//printf("No data record found\n");
				return 3;
			}
			else {
				//printf("Function failed with error: %ld\n", dwError);
				return 4;
			}
		}
	}
	else
	{
		int i = 0;
		//printf("Function returned:\n");
		//printf("\tOfficial name: %s\n", remoteHost->h_name);
		//for (auto pAlias = remoteHost->h_aliases; *pAlias != 0; pAlias++) {
		//	printf("\tAlternate name #%d: %s\n", ++i, *pAlias);
		//}
		//printf("\tAddress type: ");
		//switch (remoteHost->h_addrtype) {
		//case AF_INET:
		//	printf("AF_INET\n");
		//	break;
		//case AF_NETBIOS:
		//	printf("AF_NETBIOS\n");
		//	break;
		//default:
		//	printf(" %d\n", remoteHost->h_addrtype);
		//	break;
		//}
		//printf("\tAddress length: %d\n", remoteHost->h_length);

		i = 0;
		if (remoteHost->h_addrtype == AF_INET)
		{
			while (remoteHost->h_addr_list[i] != 0) {
				//addr.s_addr = *(u_long*)remoteHost->h_addr_list[i++];
				*ip = *(uint32_t*)remoteHost->h_addr_list[i++];
				//printf("\tIP Address #%d: %s\n", i, inet_ntoa(addr));
			}
			return 0;
		}
		else if (remoteHost->h_addrtype == AF_NETBIOS)
		{
			//printf("NETBIOS address was returned\n");
			return 5;
		}
		return 6;
	}
}