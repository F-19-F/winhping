#include "rwutil.h"
#include <pcap.h>
#include <unordered_set>
#include <IPTypes.h>
#include <iphlpapi.h>
std::string unicode_to_str(wchar_t* unistr) {
	char buf[100];
	int res = WideCharToMultiByte(CP_ACP, 0, unistr, wcslen(unistr), buf, 100, NULL, NULL);
	return res > 0 ? std::string(buf, res) : std::string();
}
std::vector<iface_info> find_ifaces() {
	int i = 0;
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Retrieve the device list */
	// 遍历所有接口
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// 存储findalldevs返回的接口信息
	std::unordered_set<std::string> pcap_ifaces;
	for (pcap_if_t* d = alldevs; d; d = d->next) {
		pcap_ifaces.insert(d->name);
		//printf("%s\n", d->name);
	}

	//释放所有接口
	pcap_freealldevs(alldevs);

	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;
	ULONG size = 10 * 1024;
	std::vector<uint8_t> buf(size);

	//获取所有的接口的地址信息
	ULONG res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)&buf[0], &size);
	if (res == ERROR_BUFFER_OVERFLOW) {
		buf.resize(size);
		res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)&buf[0], &size);
	}
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Can't get list of adapters: %d\n", res);
		exit(1);
	}


	//返回结果存储
	std::vector<iface_info> ifaces;

	//定义指针p来遍历winapi返回的接口信息
	IP_ADAPTER_ADDRESSES* p = (IP_ADAPTER_ADDRESSES*)&buf[0];


	for (; p; p = p->Next) {
		//printf("%s\n", p->AdapterName);
		// 如果pcap返回结果中不存在这样的接口
		if (pcap_ifaces.count(std::string("\\Device\\NPF_") + p->AdapterName) == 0) {
			//printf("count:%s\n", p->AdapterName);
			continue;
		}
		if (p->OperStatus != IfOperStatusUp) {
			//printf("up:%s\n", p->AdapterName);
			continue;
		}
		iface_info ii{};
		//存储接口索引
		ii.ifIndex = p->IfIndex;
		//存储接口名(pcap打开接口的第一个参数)
		ii.name = std::string("\\Device\\NPF_") + p->AdapterName;
		//存储描述信息
		ii.description = unicode_to_str(p->Description) + " (" + unicode_to_str(p->FriendlyName) + ")";
		//存储mac地址
		memcpy(ii.mac, p->PhysicalAddress, 6);
		//存储网卡ip地址
		if (p->FirstUnicastAddress) {
			memcpy(ii.ip, &((sockaddr_in*)p->FirstUnicastAddress->Address.lpSockaddr)->sin_addr, 4);
			ii.prefixlen = p->FirstUnicastAddress->OnLinkPrefixLength;
		}
		//排除IP地址为 0.0.0.0
		if (*((uint32_t*)(ii.ip)) == 0)
		{
			continue;
		}
		//存储网关地址
		if (p->FirstGatewayAddress) {
			memcpy(ii.gateway, &((sockaddr_in*)p->FirstGatewayAddress->Address.lpSockaddr)->sin_addr, 4);
		}
		// 存入本次循环获取到的信息
		ifaces.push_back(std::move(ii));
	}
	return ifaces;
}