#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <memory.h>
#include <iphlpapi.h>
#include <winsock.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <atomic>
#include "_internet.h"
#include "win32c.h"
#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	wchar_t path[MAX_PATH];

	if (!GetSystemDirectory(path, sizeof(path) / sizeof(*path) - sizeof(L"\\Npcap") / sizeof(wchar_t))) {
		return false;
	}
	wcscat_s(path, L"\\Npcap");
	SetDllDirectory(path);
	return true;
}
#endif
#define DEFAULT_INTERVAL 1000
#define DEFAULT_TTL 64
uint8_t packets[1514] = { 0 };
uint16_t id = 123;
bool raw_ip = false;
bool is_domain = false;
int count = -1;
int ttl = DEFAULT_TTL;
std::atomic<bool> stop;
std::string input_target;
std::string fake_ip;
int packet_send = 0;
int packet_receive = 0;
int time_sum = 0;
bool set_df = false;
bool icmp_flood = false;
int datagram_size = 0;
unsigned long long min_rtt=MAXULONGLONG;
unsigned long long max_rtt=0;
unsigned long long sum_rtt=0;
// 类型转换函数
std::string ip_to_str(const uint8_t ip[4]) {
	return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}
std::string mac_to_str(const uint8_t mac[6]) {
	char s[18];
	sprintf_s(s, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return std::string(s, 17);
}
//返回头部大小
int EtherHeaders(uint8_t* packet,const uint8_t* dst_mac,const uint8_t* src_mac, uint16_t ethertype)
{
	EthHeader* eth = (EthHeader*)packet;
	memcpy(eth->dest, dst_mac, 6);
	memcpy(eth->src, src_mac, 6);
	eth->ethertype = htons(ethertype);
	return 14;
}

//生成IPv4的数据报
/*
@param (数据包(以太网头部之后的地址)，目的ip，源ip,协议,TTL,标志位和片偏移的或运算结果,数据部分长度)
*/
int GenDatagramV4(uint8_t* packet, uint8_t* dst,const uint8_t* src, uint16_t data_len, uint16_t id , uint16_t flag_offset,uint8_t ttl, uint8_t proto)
{
	IpHeader* ip = (IpHeader*)packet;
	//IPv4
	ip->version = 4;
	ip->hdrlen = 5;
	//区分服务一般情况下不使用
	ip->tos = 0x00;
	//计算总长度(头部20+数据端长度)
	ip->len = htons(20 + data_len);
	//指定id
	ip->id = htons(id);
	//标志位和偏移
	ip->flag_offset = htons(flag_offset);
	//指定生存时间
	ip->ttl = ttl;
	//指定协议
	ip->proto = proto;
	//复制目的IP
	memcpy(ip->dest, dst, 4);
	//复制源IP
	memcpy(ip->src, src, 4);
	//设置校验和为0
	ip->csum = 0x0000;
	//计算首部校验和
	ip->csum=htons(CheckSum(packet,20));
	return 20;
}
int gettimeofday(struct timeval* tp, struct timezone* tzp) {
	namespace sc = std::chrono;
	sc::system_clock::duration d = sc::system_clock::now().time_since_epoch();
	sc::seconds s = sc::duration_cast<sc::seconds>(d);
	tp->tv_sec = (long)s.count();
	tp->tv_usec = (long)sc::duration_cast<sc::microseconds>(d - s).count();
	return 0;
}
int GenICMPEcho(uint8_t *packet, uint16_t id , uint16_t seq)
{
	icmp* i = (icmp*)packet;
	i->icmp_type = 0x08;
	i->icmp_code = 0x00;
	i->icmp_id = htons(id);
	i->icmp_seq = htons(seq);
	//在icmp头部加入时间戳,秒，微秒
	gettimeofday((struct timeval*)i->icmp_data, NULL);
	i->icmp_cksum = htons(0x0000);
	i->icmp_cksum = htons(CheckSum(packet, 8+8));
	return 8+8;
}
//发送 echo request
void SendPing(pcap_t *dev ,uint8_t *dst_mac, uint8_t * dst, const iface_info& iface,int interval ,int times)
{
	uint8_t* srcip = (uint8_t*)iface.ip;
	if (!fake_ip.empty())
	{
		auto fip = inet_addr(fake_ip.c_str());
		if (fip == INADDR_NONE)
		{
			printf("invalid fake ip\n");
			stop = true;
			return;
		}
		srcip = (uint8_t*)&fip;
	}
	// 等待监听
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	if (!is_domain)
	{
		printf("PING %s via %s (IP=%s)\n", ip_to_str(dst).c_str(), iface.description.c_str(), ip_to_str(iface.ip).c_str());
	}
	else
	{
		printf("PING %s(%s) via %s (IP=%s)\n", ip_to_str(dst).c_str(),input_target.c_str(), iface.description.c_str(), ip_to_str(iface.ip).c_str());
	}
	uint16_t seq = 0;
	while (times--)
	{
		//循环
		if (times == -2)
		{
			times = -1;
		}
		if (stop)
		{
			return;
		}
		uint8_t pkt[2000] = { 0 };
		int packet_len = 0;
		int ip_data_len = 0;
		if (!raw_ip)
		{
			packet_len = EtherHeaders(pkt, dst_mac, iface.mac, EthType::IPv4);
		}
		ip_data_len = GenICMPEcho(pkt + packet_len + sizeof(IpHeader),id,seq);
		//根据指定大小发送数据
		if (ip_data_len < datagram_size - 20)
		{
			ip_data_len = datagram_size - 20;
		}
		uint16_t flag_offset = 0x0000;
		if (set_df)
		{
			// DF标志位
			flag_offset = 0x4000;
		}
		packet_len += GenDatagramV4(pkt + packet_len, dst, srcip, ip_data_len, 1,flag_offset, ttl, IpProto::ICMP);
		packet_len += ip_data_len;
		int r = pcap_sendpacket(dev, pkt, packet_len);
		if (r == 0)
		{
			packet_send++;
			seq++;
		}
		else
		{
			printf("send packet:%s\n", pcap_geterr(dev));
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(interval));
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(interval));
	stop = true;
}
// 解析reply
void UnPackIcmp( uint8_t *dev, const struct pcap_pkthdr* hdr,const uint8_t* packet )
{
	if (stop)
	{
		pcap_breakloop((pcap_t*)dev);
	}
	EthHeader* p = (EthHeader*) packet;
	int ethsize = sizeof(EthHeader);
	if (raw_ip)
	{
		ethsize = 0;
	}
	struct timeval tv, * tp;
	struct icmp* imp;
	unsigned long long triptime;
	int ihdr_size = 0;
	if (raw_ip|| p->ethertype == htons(EthType::IPv4))
	{
		//printf("IPv4!\n");
		IpHeader* i = (IpHeader*)(packet + ethsize);
		if (i->proto == IpProto::ICMP)
		{
			ihdr_size = i->hdrlen*4;
			gettimeofday(&tv, NULL);
			//printf("ICMP\n");
			imp = (icmp*)(packet + ethsize + ihdr_size);
			if (imp->icmp_type == 11)
			{
				printf("Time-to-live exceeded message from %s\n", ip_to_str(i->src).c_str());
			}
			if (imp->icmp_id != htons(id))
			{
				return;
			}
			if (imp->icmp_type == 0x00)
			{
				tp = (struct timeval*)imp->icmp_data;
				//printf("tp:%lu", tp->tv_usec);
				//printf("tv:%lu", tv.tv_usec);
				if ((tv.tv_usec -= tp->tv_usec) < 0) {
					--tv.tv_sec;
					tv.tv_usec += 1000000;
				}
				// 计算秒数
				tv.tv_sec -= tp->tv_sec;

				// 计算传送时间,
				triptime = (unsigned long long)tv.tv_sec * 1000000 + tv.tv_usec;
				printf(" %d bytes from %s icmp_seq=%-5u ttl=%d time=%3llu.%-3llums\n",ntohs(i->len) - ihdr_size,ip_to_str(i->src).c_str(),ntohs(imp->icmp_seq),i->ttl, triptime / 1000, triptime % 1000);
				packet_receive++;
				if (triptime > max_rtt)
				{
					max_rtt = triptime;
				}
				if (triptime < min_rtt)
				{
					min_rtt = triptime;
				}
				sum_rtt += triptime;
			}
		}
	}
}
void Ping_Result(int i)
{
	printf("\n--- %s ping statistics ---\n", input_target.c_str());
	printf("%ld packets transmitted, ", packet_send);
	printf("%ld packets received, ", packet_receive);
	//if (nrepeats)
	//	printf("%ld duplicates, ", nrepeats);
	if (packet_send != packet_receive)
		printf("%ld%% packet loss\n",
			(packet_send - packet_receive) * 100 / packet_send);
	if (packet_receive != 0)
	{
		printf("round-trip min/avg/max = %llu.%llu/%llu.%llu/%llu.%llu ms\n",
			min_rtt / 1000, min_rtt % 1000,
			(sum_rtt / packet_receive) / 1000, (sum_rtt / packet_receive) % 1000,
			max_rtt / 1000, max_rtt % 1000);
	}
		stop = true;
		exit(0);
}
int PingV4(uint8_t* dst, const iface_info& iface,int times , int interval , bool target_is_local)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	//打开指定设备
	auto dev = pcap_create(iface.name.c_str(), errbuf);
	//设置立即模式，以降低延迟
	pcap_set_immediate_mode(dev, 1);
	pcap_activate(dev);
	if (!dev)
	{
		return -1;
	}
	// 判断接口类型
	auto data_link_type = pcap_datalink(dev);
	if (data_link_type == DLT_EN10MB)
	{
		;
	}
	else if ( data_link_type == DLT_RAW)
	{
		raw_ip = true;
	}
	else
	{
		printf("不支持的数据链路类型\n");
		return -1;
	}
	uint8_t dst_mac[6];
	//不需要arp解析
	if (!raw_ip)
	{
		if (target_is_local)
		{
			if (!arp_request(iface, dst, dst_mac))
			{
				fprintf(stderr, "error in arp request");
				return -2;
			}
		}
		//不是本地主机，则把目标mac地址设为网关的
		else
		{
			if (!arp_request(iface, iface.gateway, dst_mac))
			{
				fprintf(stderr, "error in arp request");
				return -2;
			}
		}
	}
	std::thread t1(SendPing, dev, dst_mac, dst, iface ,interval ,times);
	t1.detach();
	//主循环
	pcap_loop(dev,-1,(pcap_handler)UnPackIcmp, (uint8_t*)dev);
	pcap_close(dev);
	Ping_Result(0);
	return 0;
}
void dos_ping_send(pcap_t* dev, uint8_t* dst_mac, uint8_t* dst, const iface_info& iface ,int size)
{
	uint8_t* srcip = (uint8_t*)iface.ip;
	if (!fake_ip.empty())
	{
		auto fip = inet_addr(fake_ip.c_str());
		if (fip == INADDR_NONE)
		{
			printf("invalid fake ip\n");
			stop = true;
			return;
		}
		srcip = (uint8_t*)&fip;
	}
	// 等待监听
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	if (!is_domain)
	{
		printf("PING %s via %s (IP=%s)\n", ip_to_str(dst).c_str(), iface.description.c_str(), ip_to_str(iface.ip).c_str());
	}
	else
	{
		printf("PING %s(%s) via %s (IP=%s)\n", ip_to_str(dst).c_str(), input_target.c_str(), iface.description.c_str(), ip_to_str(iface.ip).c_str());
	}
	uint16_t seq = 0;
	pcap_send_queue* squeue;
	squeue = pcap_sendqueue_alloc(1514*1000);
	struct pcap_pkthdr pktheader;
	while (true)
	{
		if (stop)
		{
			return;
		}
		uint8_t pkt[1514] = { 0 };
		int packet_len = 0;
		int icmp_start = 0;
		int ip_data_len = 0;
		if (!raw_ip)
		{
			icmp_start = packet_len = EtherHeaders(pkt, dst_mac, iface.mac, EthType::IPv4);
		}
		ip_data_len = GenICMPEcho(pkt + icmp_start + sizeof(IpHeader), id, seq);
		packet_len += GenDatagramV4(pkt + packet_len, dst, srcip, ip_data_len+size, 1, 0x0000, ttl, IpProto::ICMP);
		packet_len += ip_data_len;
		gettimeofday(&pktheader.ts, NULL);
		pktheader.len = packet_len + size;
		pktheader.caplen = packet_len + size;
		//pkt[packet_len + size - 1] = 0x12;
		for (int i = 0; i < 1000; i++)
		{
			GenICMPEcho(pkt + icmp_start + sizeof(IpHeader), id, seq);
			pcap_sendqueue_queue(squeue, &pktheader, pkt);
			seq++;
			packet_send++;
		}
		pcap_sendqueue_transmit(dev, squeue, 0);
	}
}
int do_icmp_flood(uint8_t* dst, const iface_info& iface, int times, int interval, bool target_is_local,int threads)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	//打开指定设备
	auto dev = pcap_create(iface.name.c_str(), errbuf);
	//设置立即模式，以降低延迟
	pcap_set_immediate_mode(dev, 1);
	pcap_activate(dev);
	if (!dev)
	{
		return -1;
	}
	// 判断接口类型
	auto data_link_type = pcap_datalink(dev);
	if (data_link_type == DLT_EN10MB)
	{
		;
	}
	else if (data_link_type == DLT_RAW)
	{
		raw_ip = true;
	}
	else
	{
		printf("不支持的数据链路类型\n");
		return -1;
	}
	uint8_t dst_mac[6];
	//不需要arp解析
	if (!raw_ip)
	{
		if (target_is_local)
		{
			if (!arp_request(iface, dst, dst_mac))
			{
				fprintf(stderr, "error in arp request");
				return -2;
			}
		}
		//不是本地主机，则把目标mac地址设为网关的
		else
		{
			if (!arp_request(iface, iface.gateway, dst_mac))
			{
				fprintf(stderr, "error in arp request");
				return -2;
			}
		}
	}
	for (int i = 0; i < threads; i++)
	{
		std::thread(dos_ping_send, dev, dst_mac,dst, iface, 1300).detach();
	}
	while (true)
	{
		;
	};
}
int trap(uint8_t* dst, const iface_info& iface,int times , int interval , bool target_is_local){
	if(icmp_flood){
		return do_icmp_flood(dst,iface,times,interval,target_is_local,6);
	}else
	{
		return PingV4(dst,iface,times,interval,target_is_local);
	}
	
}

void print_ifaces(const std::vector<iface_info>& ifaces) {
	for (const iface_info& iface : ifaces) {
		printf("%d.\t%s\n\tip=%s/%d gateway=%s ", iface.ifIndex, iface.description.c_str(),
			ip_to_str(iface.ip).c_str(), iface.prefixlen, ip_to_str(iface.gateway).c_str());
		printf("\n");
	}
}
// 通过IP来判断从哪个接口发送请求
int Judge_Ifaces_By_RouteTable(uint8_t * ip,int &res)
{
	//Get System Route Table
	PMIB_IPFORWARDTABLE p_table;
	DWORD dwSize = 0;
	p_table = (MIB_IPFORWARDTABLE*) malloc(sizeof(MIB_IPFORWARDTABLE));
	int index = -1;
	int prefix = -1;
	//malloc error
	if (!p_table)
	{
		return -1;
	}
	// get real size to store route table
	if (GetIpForwardTable(p_table, &dwSize, 0) ==
		ERROR_INSUFFICIENT_BUFFER) {
		free(p_table);
		p_table = (MIB_IPFORWARDTABLE*)malloc(dwSize);
		if (!p_table) {
			return -1;
		}
	}
	// get route table
	if ((GetIpForwardTable(p_table, &dwSize, 0)) == NO_ERROR)
	{
		// 遍历路由表
		DWORD metric = INFINITE;
		int tmp_prefix;
		uint32_t t_subnet = 0;
		uint32_t d_subnet = 0;
		const uint32_t zero_mask = 0;
		uint32_t mask = 0;
		for (int i = 0; i < (int)p_table->dwNumEntries; i++)
		{
			// 首先判断目的地址
			// 非0.0.0.0
			if (p_table->table[i].dwForwardDest)
			{
				// 内存中都是网络中的大端
				t_subnet = *((uint32_t*)ip);
				t_subnet = t_subnet & p_table->table[i].dwForwardMask;
				d_subnet = p_table->table[i].dwForwardDest;
				d_subnet = d_subnet & p_table->table[i].dwForwardMask;
				mask = p_table->table[i].dwForwardMask;
			}
			// 0.0.0.0
			else
			{
				t_subnet = d_subnet = 0;
				mask = zero_mask;
			}
			// 不管大小端，此处均可以表示子网相同
			if (t_subnet == d_subnet)
			{
				// 比较子网长度
				tmp_prefix =  GetMaskLen(((uint8_t*)&(p_table->table[i].dwForwardMask)), 4);
				if (tmp_prefix > prefix)
				{
					prefix = tmp_prefix;
					index = p_table->table[i].dwForwardIfIndex;
					metric = p_table->table[i].dwForwardMetric1;
					//printf("%d\t%d\n", prefix,index);
				}
				// 如果子网长度相同， 比较跃点数
				else if (tmp_prefix == prefix)
				{
					if (p_table->table[i].dwForwardMetric1 < metric)
					{
						metric = p_table->table[i].dwForwardMetric1;
						index = p_table->table[i].dwForwardIfIndex;
					}
				}
			}
		}
	}
	res = index;
	return prefix;


}
int main(int argc, char** argv)
{
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "need npcap installed!\n");
		return -1;
	}
	const char* help = "Usage (by swutangtf aka f19)\n\
    .\\winhping.exe [options] <destination>\n\
	\nOptions:\n\
   <destination> dns name or address\n\
	-h\t\tshow help\n\
	-l\t\tlist interfaces and exit.\n\
	-f\t\tset DF flags.\n\
	-d\t\ticmp flood mode.\n\
	-c <count>\tstop after <count> requests.\n\
	-I <ifaceindex>\tset which interface to send ping.\n\
	-i <interval>\t milli seconds between sending each packet default 1000ms.\n\
	-t <ttl>\tdefine time to live.\n\
	-p <ip>\t\tset a fake ip to send ping echo.\n\
	-s <size>\tset ip datagram size\n"; 
	if (argc < 2)
	{
		fprintf(stderr,help);
		return -1;
	}
	auto ifaces = find_ifaces();
	std::string dst;
	int interval = DEFAULT_INTERVAL;
	if (argc == 2 && !strcmp(argv[1], "-l"))
	{
		print_ifaces(ifaces);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "-h"))
	{
		fprintf(stdout, help);
		return 0;
	}
	int index = -1;
	int ct = 0;
	argc--;
	argv++;
	while (argc > 0)
	{
		if (!strcmp(argv[0], "-s")) {
			datagram_size =atoi(argv[1]);
			argc -= 2;
			argv += 2;
			continue;
		}
		if (!strcmp(argv[0], "-f")) {
			set_df = true;
			argc -= 1;
			argv += 1;
			continue;
		}
		if (!strcmp(argv[0], "-d")) {
			icmp_flood = true;
			argc -= 1;
			argv += 1;
			continue;
		}
		if (!strcmp(argv[0], "-p")) {
			fake_ip = argv[1];
			argc -= 2;
			argv += 2;
			continue;
		}
		if (!strcmp(argv[0], "-t")) {
			ttl = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			continue;
		}
		if (!strcmp(argv[0], "-I")) {
			index = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			continue;
		}
		if (!strcmp(argv[0], "-c")) {
			count = atoi(argv[1]);
			argc-=2;
			argv+=2;
			continue;
		}
		if (!strcmp(argv[0], "-i")) {
			interval = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			continue;
		}
		if (dst.empty())
		{
			dst = argv[0];
			argv++;
			argc--;
			continue;
		}
		fprintf(stderr, "Unknown argument: %s\n", argv[0]);
		return -1;
	}
	auto bin_ip = inet_addr(dst.c_str());
	//假定是域名
	if (bin_ip == INADDR_NONE)
	{
		if (dns_request4(dst.c_str(), (uint32_t*)&bin_ip) != 0)
		{
			fprintf(stderr, "no target %s found! ", dst.c_str());
			return -2;
		}
		is_domain = true;
		input_target = dst;
	}
	bool target_is_local = false;
	int ret = -1;
	if (index == -1)
	{
		ret = Judge_Ifaces_By_RouteTable((uint8_t*)&bin_ip, index);
		if (ret == -1)
		{
			printf("No route to %s found!\n", dst.c_str());
			return -1;
		}
		else if (ret > 0)
		{
			target_is_local = true;
		}
	}
	signal(SIGINT, Ping_Result);
	for (auto i : ifaces)
	{
		if (i.ifIndex == index)
		{
			// 用户自定义接口
			if (ret == -1)
			{
				int  bit = 0;
				int j;
				for (j = 0; j < i.prefixlen; j++)
				{
					bit = 31 - j;
#ifdef CPuIS_BIG_ENDIAN
					if (bin_ip >> bit != *((uint32_t*)i.ip) >> bit)
#else
					if (bin_ip << bit != *((uint32_t*)i.ip) << bit)
#endif
					{
						break;
					}
				}
				// 目标地址与接口ip地址属于同一子网
				if (j == i.prefixlen)
				{
					target_is_local = true;
				}

			}
			trap((uint8_t*)&bin_ip, i,count,interval,target_is_local);
		}
		else
		{
			ct++;
			if (ct == ifaces.size())
			{
				printf("no index found! iface lists:\n");
				print_ifaces(ifaces);
			}
		}
	}
}


