/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

/* 子函数声明 */
int Authentication(const char *UserName, const char *Password, const char *DeviceName, const char * DHCPScript);

static struct option arglist[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"password", required_argument, NULL, 'p'},
        {"script", required_argument, NULL, 's'},
        {"iface", required_argument, NULL, 'i'},
        {NULL, 0, NULL, 0}
};

static const char usage_str[] = "usage: "
    "   njit-client -u username -p password [-i interface] [-s dhcp_script]\n"
    "   -h --help           print this screen\n"
    "   -u --user           longin name\n"
    "   -p --password       password\n"
    "   -s --script         dhcp script\n"
    "   -i --iface          network interface (default eth0)\n";

/**
 * 函数：main()
 *
 * 检查程序的执行权限，检查命令行参数格式。
 * 允许的调用格式包括：
 * 	njit-client -u username -p password
 * 	njit-client -u username -p password -i eth0
 * 	njit-client -u username -p password -i eth1 -s "dhcpcd"
 * 若没有从命令行指定网卡，则默认将使用eth0
 */
int main(int argc, char *argv[])
{
    int argval;
	char UserName[32] = "";
	char Password[32] = "";
	char DeviceName[16] = "eth0";
	char DHCPScript[128] = "";

	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		fprintf(stderr, "抱歉，运行本客户端程序需要root权限\n");
		fprintf(stderr, "(RedHat/Fedora下使用su命令切换为root)\n");
		fprintf(stderr, "(Ubuntu/Debian下在命令前添加sudo)\n");
		exit(-1);
	}

    while ((argval = getopt_long(argc, argv, "u:p:i:s:h", arglist, NULL)) != -1) {
        switch (argval) {
            case 'h':
                printf(usage_str);
                exit(EXIT_SUCCESS);
            case 'u':
                strncpy(UserName, optarg, sizeof(UserName));
                break;
            case 'p':
                strncpy(Password, optarg, sizeof(Password));
                break;
            case 'i':
                strncpy(DeviceName, optarg, sizeof(DeviceName));
                break;
            case 's':
                strncpy(DHCPScript, optarg, sizeof(DHCPScript));
                break;      
            default:
                break;
        }
    }

    if (strlen(UserName) == 0 ||
            strlen(Password) == 0 ||
            strlen(DeviceName) == 0) {
                printf(usage_str);
                exit(EXIT_SUCCESS);
    }

	/* 调用子函数完成802.1X认证 */
	Authentication(UserName, Password, DeviceName, DHCPScript);

	return (EXIT_SUCCESS);
}

