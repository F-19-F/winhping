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
	// �������нӿ�
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// �洢findalldevs���صĽӿ���Ϣ
	std::unordered_set<std::string> pcap_ifaces;
	for (pcap_if_t* d = alldevs; d; d = d->next) {
		pcap_ifaces.insert(d->name);
		//printf("%s\n", d->name);
	}

	//�ͷ����нӿ�
	pcap_freealldevs(alldevs);

	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES;
	ULONG size = 10 * 1024;
	std::vector<uint8_t> buf(size);

	//��ȡ���еĽӿڵĵ�ַ��Ϣ
	ULONG res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)&buf[0], &size);
	if (res == ERROR_BUFFER_OVERFLOW) {
		buf.resize(size);
		res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)&buf[0], &size);
	}
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Can't get list of adapters: %d\n", res);
		exit(1);
	}


	//���ؽ���洢
	std::vector<iface_info> ifaces;

	//����ָ��p������winapi���صĽӿ���Ϣ
	IP_ADAPTER_ADDRESSES* p = (IP_ADAPTER_ADDRESSES*)&buf[0];


	for (; p; p = p->Next) {
		//printf("%s\n", p->AdapterName);
		// ���pcap���ؽ���в����������Ľӿ�
		if (pcap_ifaces.count(std::string("\\Device\\NPF_") + p->AdapterName) == 0) {
			//printf("count:%s\n", p->AdapterName);
			continue;
		}
		if (p->OperStatus != IfOperStatusUp) {
			//printf("up:%s\n", p->AdapterName);
			continue;
		}
		iface_info ii{};
		//�洢�ӿ�����
		ii.ifIndex = p->IfIndex;
		//�洢�ӿ���(pcap�򿪽ӿڵĵ�һ������)
		ii.name = std::string("\\Device\\NPF_") + p->AdapterName;
		//�洢������Ϣ
		ii.description = unicode_to_str(p->Description) + " (" + unicode_to_str(p->FriendlyName) + ")";
		//�洢mac��ַ
		memcpy(ii.mac, p->PhysicalAddress, 6);
		//�洢����ip��ַ
		if (p->FirstUnicastAddress) {
			memcpy(ii.ip, &((sockaddr_in*)p->FirstUnicastAddress->Address.lpSockaddr)->sin_addr, 4);
			ii.prefixlen = p->FirstUnicastAddress->OnLinkPrefixLength;
		}
		//�ų�IP��ַΪ 0.0.0.0
		if (*((uint32_t*)(ii.ip)) == 0)
		{
			continue;
		}
		//�洢���ص�ַ
		if (p->FirstGatewayAddress) {
			memcpy(ii.gateway, &((sockaddr_in*)p->FirstGatewayAddress->Address.lpSockaddr)->sin_addr, 4);
		}
		// ���뱾��ѭ����ȡ������Ϣ
		ifaces.push_back(std::move(ii));
	}
	return ifaces;
}