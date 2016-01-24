/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

//int Authentication(const char *UserName, const char *Password, const char *DeviceName, const char *DHCPScript);

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <pcap/pcap.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if_dl.h>

#include "debug.h"

// 自定义常量
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20} EAP_Type;
typedef uint8_t EAP_ID;
const uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const unsigned char H3cVersion[32] = "\006\007b2BcGRxWNXQtTExmJgR5fSpGmRU=  ";

// 子函数声明
static void SendStartPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendLogoffPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendResponseIdentity(pcap_t *adhandle,
			const uint8_t request[],
			const uint8_t ethhdr[],
            const char username[]);
static void SendResponseMD5(pcap_t *adhandle,
		const uint8_t request[],
		const uint8_t ethhdr[],
		const char username[],
		const char passwd[]);
static void GetMacFromDevice(uint8_t mac[6], const char *devicename);
// From fillmd5.c
extern void FillMD5Area(uint8_t digest[],
	       	uint8_t id, const char passwd[], const uint8_t srcMD5[]);



/**
 * 函数：Authentication()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

int Authentication(const char *UserName, const char *Password, const char *DeviceName, const char *DHCPScript)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*adhandle; // adapter handle
	uint8_t	MAC[6]; // 本机地址
	char	FilterStr[250];
	struct bpf_program	fcode;

	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良

	/* 打开适配器(网卡) */
	adhandle = pcap_create(DeviceName,errbuf);
	if (adhandle==NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(-1);
	}
    pcap_set_promisc(adhandle,1);
    pcap_set_snaplen(adhandle,512);
    pcap_setdirection(adhandle,PCAP_D_IN);
    pcap_set_timeout(adhandle,1000);
  	pcap_activate(adhandle);

	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	/*
	 * 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息
	 */
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(adhandle, &fcode);



	START_AUTHENTICATION:
	{
		int retcode;
		struct pcap_pkthdr *header;
		const uint8_t	*captured;
		uint8_t	ethhdr[14]={0}; // ethernet header

		/* 主动发起认证会话 */
		DPRINTF("[   ] Client: Start.\n");
		/* 等待认证服务器的回应 */
		bool serverIsFound = false;
		while (!serverIsFound)
		{
			SendStartPkt(adhandle, MAC);
			retcode = pcap_next_ex(adhandle, &header, &captured);
			if (retcode==1 && (EAP_Code)captured[18]==REQUEST && (EAP_Type)captured[22] == IDENTITY) {
				serverIsFound = true;
			}
			else
			{
				DPRINTF(".");
				sleep(1);
				//SendStartPkt(adhandle, MAC);
				// NOTE: 这里没有检查网线是否接触不良或已被拔下
			}
		}

		// 填写应答包的报头(以后无须再修改)
		// 默认以单播方式应答802.1X认证设备发来的Request
		memcpy(ethhdr+0, captured+6, 6);
		memcpy(ethhdr+6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// 分情况应答下一个包
		if ((EAP_Type)captured[22] == IDENTITY)
		{	// 通常情况会收到包Request Identity，应回答Response Identity
			DPRINTF("[%3d] Server: Request Identity!\n", captured[19]);
			SendResponseIdentity(adhandle, captured, ethhdr, UserName);
			DPRINTF("[%3d] Client: Response Identity.\n", (EAP_ID)captured[19]);
		}

		// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x) and ((ether dst host %02x:%02x:%02x:%02x:%02x:%02x) or (ether dst host %02x:%02x:%02x:%02x:%02x:%02x))",
			captured[6],captured[7],captured[8],captured[9],captured[10],captured[11],
            MultcastAddr[0],MultcastAddr[1],MultcastAddr[2],MultcastAddr[3],MultcastAddr[4],MultcastAddr[5],
            MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, PCAP_NETMASK_UNKNOWN);
		pcap_setfilter(adhandle, &fcode);

		// 进入循环体
		for (;;)
		{
			// 调用pcap_next_ex()函数捕获数据包
			while (pcap_next_ex(adhandle, &header, &captured) != 1)
			{
				//DPRINTF("."); // 若捕获失败，则等1秒后重试
				//sleep(1);     // 直到成功捕获到一个数据包后再跳出
				// NOTE: 这里没有检查网线是否已被拔下或插口接触不良
			}

			// 根据收到的Request，回复相应的Response包
			if ((EAP_Code)captured[18] == REQUEST)
			{
				switch ((EAP_Type)captured[22])
				{
				 case IDENTITY:
					DPRINTF("[%3d] Server: Request Identity!\n", (EAP_ID)captured[19]);
                    SendResponseIdentity(adhandle, captured, ethhdr, UserName);
					DPRINTF("[%3d] Client: Response Identity.\n", (EAP_ID)captured[19]);
					break;
				 case MD5:
					DPRINTF("[%3d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
					SendResponseMD5(adhandle, captured, ethhdr, UserName, Password);
					DPRINTF("[%3d] Client: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
					break;
				 default:
					DPRINTF("[%3d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
					DPRINTF("Error! Unexpected request type\n");
					exit(-1);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{	// 处理认证失败信息
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*) &captured[24];
				DPRINTF("[%3d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype==0x09 && msgsize>0)
				{	// 输出错误提示消息
					DPRINTF("errtype=0x%02x\n", errtype);
					fprintf(stderr, "%s\n", msg);
					// 已知的几种错误如下
					// E2531:用户名不存在
					// E2535:Service is paused
					// E2542:该用户帐号已经在别处登录
					// E2547:接入时段限制
					// E2553:密码错误
					// E2602:认证会话不存在
					// E3137:客户端版本号无效
					exit(-1);
				}
				else if (errtype==0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{	// 遇此情况客户端立刻发起新的认证会话
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					fprintf(stderr, "%s\n", msg);
					//exit(-1);
					goto START_AUTHENTICATION;
				}
			}
			else if ((EAP_Code)captured[18] == SUCCESS)
			{
				DPRINTF("[%3d] Server: Success.\n", captured[19]);
				// 刷新IP地址
				system(DHCPScript);
			}
			else
			{
				DPRINTF("[%3d] Server: (H3C data)\n", captured[19]);
				// TODO: 这里没有处理华为自定义数据包
			}
		}
	}
	return (0);
}


static
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
	struct ifaddrs *ifa;
    int err;
    err = getifaddrs(&ifa);
	assert(err != -1);

	assert(strlen(devicename) < IFNAMSIZ);

    while(ifa) {
        if (strcmp(ifa->ifa_name, devicename) == 0) {
            if (ifa->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                uint8_t *m = (uint8_t *)LLADDR(sdl);
                memcpy(mac, m, 6);
                break;
            }
        }
        ifa = ifa->ifa_next;
    }
    assert(ifa != NULL);
}

static
void SendStartPkt(pcap_t *handle, const uint8_t localmac[])
{
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x01;	// Type=Start
	packet[16] = packet[17] =0x00;// Length=0x0000

	// 多播发送Strat包
    memcpy(packet, MultcastAddr, 6);
	pcap_sendpacket(handle, packet, sizeof(packet));
}



static
void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[], const uint8_t ethhdr[], const char username[])
{
	uint8_t	response[128];
	size_t packetlen;
	uint16_t eaplen;
	int usernamelen;

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == IDENTITY);

    usernamelen = strlen(username); //末尾添加用户名
    packetlen = 55 + usernamelen;
	eaplen = htons(packetlen-18);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		memcpy(response+16, &eaplen, sizeof(eaplen));	// Length
		// Extensible Authentication Protocol
		// {
			response[18] = (EAP_Code) RESPONSE;	// Code
			response[19] = request[19];		// ID
            response[20] = response[16];	// Length
            response[21] = response[17];	//
			response[22] = (EAP_Type) IDENTITY;	// Type
			// Type-Data
			// {
				memcpy(response+23, H3cVersion, 32);
				memcpy(response+55, username, usernamelen);
				assert(packetlen <= sizeof(response));
			// }
		// }
	// }

	// 补填前面留空的两处Length
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(adhandle, response, packetlen);
	return;
}

static
void SendResponseMD5(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[], const char username[], const char passwd[])
{
	uint16_t eaplen;
	size_t   usernamelen;
	size_t   packetlen;
	uint8_t  response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == MD5);

	usernamelen = strlen(username);
	packetlen = 40+usernamelen; // ethhdr+EAPOL+EAP+usernamelen
	eaplen = htons(packetlen - 18);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
		response[14] = 0x1;	// 802.1X Version 1
		response[15] = 0x0;	// Type=0 (EAP Packet)
		memcpy(response+16, &eaplen, sizeof(eaplen));	// Length

		// Extensible Authentication Protocol
		// {
		response[18] = (EAP_Code) RESPONSE;// Code
		response[19] = request[19];	// ID
		response[20] = response[16];	// Length
		response[21] = response[17];	//
		response[22] = (EAP_Type) MD5;	// Type
		response[23] = 16;		// Value-Size: 16 Bytes
		FillMD5Area(response+24, request[19], passwd, request+24);
		memcpy(response+40, username, usernamelen);
		// }
	// }

	pcap_sendpacket(handle, response, packetlen);
}

/*
static
void SendLogoffPkt(pcap_t *handle, const uint8_t localmac[])
{
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet, MultcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x02;	// Type=Logoff
	packet[16] = 0x00;
    packet[17] = 0x00;// Length=0x0000

	// 发包
	pcap_sendpacket(handle, packet, sizeof(packet));
}

*/
