---
title: 使用 MITM6 中继 WPAD 身份验证
date: 2022-03-26 08:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Active Directory", "NTLM Relay", "Mitm"]
layout: post
---

2018 年对于攻击性社区来说是非常好的一年，因为 Dirk-jan Mollema（[@dirkjanm](https://twitter.com/_dirkjan)）公布了有关基于 IPv6 中间人攻击的研究。在现代 Windows 操作系统中，默认情况下将启用 IPv6。这意味着系统会定期轮询 IPv6 配置，因为 IPv6 是比 IPv4 更新的协议，因此在 Microsoft 操作系统中，IPv6 的优先级将高于 IPv4。

然而，在绝大多数组织中，攻击者可以劫持客户端的 IPv6 DHCP 请求，并通过设置 DNS 服务器等方式，强制客户端对攻击者控制的服务器进行身份验证。这将为后续的 NTLM Relay 攻击铺平道路。

在本篇文章，我将对这种攻击思路进行讲解和演示，尽管这已经不是什么新技术了。



## WPAD

通常情况下，若要为组织中的所有浏览器提供相同的代理策略，而无需手动配置每个浏览器，需要使用下列两种技术：

- 代理自动配置（PAC）标准：创建和发布一个中央代理自动配置文件。
- 网络代理自动发现协议（WPAD）标准：确保组织中的浏览器在非手动配置的情况下找到这个 PAC 文件。

网络代理自动发现协议（Web Proxy Auto-Discovery Protocol，WPAD）是一种客户端使用 DHCP 或 DNS 发现来定位一个配置文件 URL 的方法。在检测和下载配置文件后，它可以执行代理配置文件以测定特定 URL 应使用的代理。

代理自动配置文件（Proxy Auto-Config，简称 PAC，一般是 wpad.bat）定义了浏览器和其他用户代理如何自动选择适当的代理服务器来访问一个 URL。要使用 PAC，我们应当在一个网页服务器上发布一个 PAC 文件，并且通过在浏览器的代理链接设置页面输入这个 PAC 文件的 URL 地址或者通过使用 WPAD 协议告知用户自动检测并去使用这个文件。

默认情况下，计算机将使用 “自动检测设置”，如下图所示。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220416203216508.png)

WPAD 协议通过让浏览器自动发现代理服务器，定位代理配置文件，下载编译并运行，最终自动使用代理访问网络。

代理自动配置文件 PAC 的格式如下：

```php
function FindProxyForURL(url, host) {
   if (url== 'http://www.baidu.com/') return 'DIRECT';
   if (host== 'twitter.com') return 'SOCKS 127.0.0.10:7070';
   if (dnsResolve(host) == '10.0.0.100') return 'PROXY 127.0.0.1:8086;DIRECT';
   return 'DIRECT';
}
```

WPAD 协议自动定位配置文件的一般请求流程如下图所示：

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417125127006.png)

用户在访问网页时，首先会查询 PAC 文件的位置，然后获取 PAC 文件，将 PAC 文件作为代理配置文件。其中，查询 PAC 文件的顺序如下：

1. 通过 DHCP 服务器查询
2. 查询 WPAD 服务器的 IP 地址
   - Hosts
   - DNS（Cache/Server）
   - LLMNR
   - NBNS

在这个过程中，主要涉及到两种攻击方式。

## LLMNR/NBNS Poison

这是早期针对 WPAD 的攻击思路。当计算机开启 “自动检测设置” 后，用户在访问网页时，首先会查询 PAC 文件的位置。假设用户的计算机网络名称为 pc.department.branch.example.com，那么浏览器将依次尝试在下列 URL 中定位 PAC 文件，以期成功在客户端的所在的域或父域中找到一个代理配置文件：

- http://wpad.department.branch.example.com/wpad.dat
- http://wpad.branch.example.com/wpad.dat
- http://wpad.example.com/wpad.dat
- http://wpad.com/wpad.dat

如果上述域名没有在域内进行专门配置的话，那么将导致 DNS 解析失败，此时客户端就会使用 LLMNR/NBNS 协议分别向局域网内发送 UDP 多播或广播请求，以查询 WPAD 服务器对应的 IP 地址。这就允许攻击者对当前网络实施 LLMNR/NBNS 投毒，并声称攻击者所控的服务器就是 WPAD 服务器。当客户端访问攻击者伪造的 WPAD 服务器时，攻击者可以诱使客户端向攻击者的服务器发起 NTLM 认证。攻击者可以截获客户端发来的 Net-NTLM Hash 并重放到其他服务，从而实现 NTLM Relay。

关于 LLMNR/NBNS 投毒的细节，请自行上网查阅相关资料，这里不再赘述。下面我对相关利用进行演示。

（1）首先在攻击者可控的服务器上启动 Responder 监听，相关命令如下。执行后，Responder 将伪造一个 WPAD 服务器。

```bash
responder -I eth0 -rPdv
```

（2）当客户端用户在访问网页时，由于 IE 浏览器默认是自动检测设置，所以首先会查询 PAC 文件的位置，如果本地 Hosts 文件和 DNS 服务器解析不到这个域名地址的话，就会转而使用 LLMNR/NBNS 协议进行解析。此时，Responder 通过 LLMNR/NBNS 投毒将 WPAD 服务器的 IP 地址指向 Responder 所在的服务器。然后，Responder 通过伪造如下 PAC 文件将代理指向 `ISAProxySrv:3141`：

```php
function FindProxyForURL(url, host){
    if ((host == "localhost") 
        || shExpMatch(host, "localhost.*") 
        ||(host == "127.0.0.1") 
        || isPlainHostName(host)) return "DIRECT"; 
    if (dnsDomainIs(host, "ProxySrv")
        ||shExpMatch(host, "(*.ProxySrv|ProxySrv)")) return "DIRECT"; 
    return 'PROXY ProxySrv:3128; PROXY ProxySrv:3141; DIRECT';}
```

（3）客户端会使用 `ProxySrv:3141` 作为代理地址，但是受害者不知道 `ProxySrv` 对应的 IP 是什么，所以会再次触发查询，Responder 将再次通过 LLMNR/NBNS 投毒进行欺骗。将 `ProxySrv` 名词所对应的地址指向 Responder 服务器本身。这样攻击者最终可以劫持客户端的 HTTP 流量，并通过在其流量中插入 XSS 向量、回复 HTTP 407 错误等方式来诱使客户端发起 NTLM 认证。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417102852320.png)

值得注意的是，我们可以在 Responder 上开启 `-F` 选项，当客户端索取 wpad.dat 文件时就立即强制其执行 NTLM 认证，如下图所示。但由于该设置可能会弹出登录框，因此默认关闭。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417103104600.png)

然而，微软在 2016 年发布了 MS16-077 安全公告，添加了两个重要的保护措施，以缓解此类攻击行为：

- 系统再也无法通过多播或广播协议来解析 PAC 文件的位置。也就是说 LLMNR/NBNS 协议不再用于自动获取 WPAD 服务器的位置，只能通过使用 DHCP 或 DNS 协议完成该任务。
- 更改了 PAC 文件下载的默认行为，以便当 WinHTTP 请求 PAC 文件时，不会自动发送客户端的凭据来响应 NTLM 或协商身份验证质询。也就是说即便在 Responder 上开启 `-F` 选项，客户端也不会发起 NTLM 认证。

对于第二个保护措施，我们很容易便能绕过。因为在默认情况下，Responder 本就不想在这一步获取 Net-NTLM Hash，除非我们手动开启 `-F` 选项。而更多情况下，我们是给用户返回一个正常的 PAC 文件，并通过 PAC 文件将代理指向攻击者自己，然后我们便可以实现中间人的角色。这个时候可以做的事就很多了，例如在客户端的流量中插入 XSS 向量、窃取 POST Body 以及 Cooke 等参数、通过 HTTP 基本身份认证进行钓鱼、诱使客户端下载木马程序等。

此外，当客户端主机连接到攻击者的 “代理” 服务器时，我们可以通过 HTTP CONNECT 行为或者 GET 请求所对应的完整 URI 路径来识别这个过程，然后回复 HTTP 407 错误来强制客户端进行代理身份验证。IE/Edge 以及 Chrome 浏览器会自动与代理服务器进行身份认证，即使在最新版本的 Windows 系统上也是如此。在 Firefox 中，用户可以配置这个选项，该选项默认处于启用状态。

至此，我们可以成功绕过第二个保护措施。接下来我们需要重点绕过第一个保护措施。

## MITM6

MS16-077 之后，系统再也无法通过多播或广播协议来解析 PAC 文件的位置。也就是说 LLMNR/NBNS 协议不再用于自动获取 WPAD 服务器的位置，只能通过使用 DHCP 或 DNS 协议完成该任务。但是 DHCP 和 DNS 都有指定的服务器，不是通过多播或广播请求，并且大部分情况下 DHCP 服务器和 DNS 服务器我们是不可控的，因此无法进行投毒。

幸运的是，安全研究人员并不将眼光局限于 IPv4。从 Windows Vista 以来，所有的 Windows 系统都会启用 IPv6 网络，并且其优先级要高于 IPv4 网络。在 DHCPv6 协议中，客户端将定期通过向多播地址发送 Solicit 报文来定位 DHCPv6 服务器，并与 DHCPv6 服务器执行消息交换，以获取 IPv6 地址和相关配置设置，如下图所示。多播地址 `[ff02::1:2]` 包括整个地址链路范围内的所有 DHCPv6 服务器和中继代理。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417204057986.png)

在 DHCPv6 协议中，客户端使用 UDP 546 端口，服务器使用 547 端口。DHCPv6 的四步交互过程如下，其中 DHCPv6 服务器的链路本地地址是 `fe80::0011:22ff:fe33:5566`，客户端的链路本地地址是 `fe80::aabb:ccff:fedd:eeff`。

1. 客户端从 `[fe80::aabb:ccff:fedd:eeff]:546` 向多播地址 `[ff02::1:2]:547` 发送一个 Solicit 请求报文，以定位有效的 DHCPv6 服务器。
2. DHCP 服务器从 `[fe80::0011:22ff:fe33:5566]:547` 给 `[fe80::aabb:ccff:fedd:eeff]:546` 回应一个 Advertise 消息，以告知客户端其可以提供 IPv6 地址和配置设置。
3. 客户端从 `[fe80::aabb:ccff:fedd:eeff]:546` 向多播地址 `[ff02::1:2]:547` 发送一个 Request 消息，以请求分配 IPv6 地址和相关配置信息。（依照 RFC 8415 规范，所有 DHCPv6 客户端的消息都发送到多播地址）
4. 最后服务器从 `[fe80::0011:22ff:fe33:5566]:547` 给 `[fe80::aabb:ccff:fedd:eeff]:546` 回应一个包含了确认地址，委托前缀和相关配置（如可用的 DNS 或 NTP 服务器等）的 Reply 消息。

由于 Windows Vista 版本以后的系统默认启用了 IPv6 网络，如果攻击者能截获客户端发送的 DHCPv6 多播数据包，那么攻击者可以将受害者的 DNS 设置为攻击者的 IPv6 地址。

[@dirkjanm](https://twitter.com/_dirkjan) 早在 2018 年就公布了一个名为 [mitm6](https://github.com/dirkjanm/mitm6) 的工具，可以用来实施此类攻击。mitm6 可以利用 Windows 的默认配置来接管默认的 DNS 服务器。它通过回复 DHCPv6 消息，为受害者提供链接本地 IPv6 地址并将攻击者主机设置为默认 DNS 服务器来实现此目的。作为 DNS 服务器，mitm6 将选择性地回复攻击者选择的 DNS 查询，并将受害者流量重定向到攻击者机器而不是合法服务器。

（1）首先在攻击者服务器上执行以下命令，监听某个网卡上的 DHCPV6 流量，如下图所示。

```bash
mitm6 -d pentest.com -i eth0
```

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417111026219.png)

（2)记录当前攻击者服务器的 IPv6 地址为 `fe80::20c:29ff:fee2:1920`。当客户端向 DHCPv6 轮询 IPv6 网络配置时，mitm6 将回复这些 DHCPv6 请求，并在本地链接范围内为客户端分配一个 IPv6 地址。尽管在实际的 IPv6 网络中，这些地址是由主机自己自动分配的，不需要由 DHCP 服务器配置，但这使我们有机会将攻击者 IP 设置为客户端默认的 IPv6 DNS 服务器。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417113259272.png)

如下图所示，此时客户端的 DNS 服务器的地址已经设置为攻击者的 IPv6 地址，成功接管客户端的 DNS。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417110409990.png)

我们对整个攻击过程进行抓包，如下图所示。可以看到客户端从 `fe80::2593:ea01:af72:5623` 向多播地址 `ff02::1:2` 发送 Solicit 消息，此时攻击者的 mitm6 从 `fe80::20c:29ff:fee2:1920` 给客户端响应 Advertise 消息，之后攻击者代替真正的 DHCPv6 服务器来与进行客户端交互。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417205724544.png)

（3）一旦客户端机器将攻击者设置为 IPv6 DNS 服务器，它将立即通过 DNS 不断查询网络的 WPAD 配置。但此时这些查询消息都发送给了攻击者，因此攻击者将使用自己的 IP 地址作为 WPAD 对应的 IP 地址，并通过伪造 PAC 文件将代理指向攻击者自己，以并强制客户端执行 NTLM 认证。如下图所示，Responder 上先接收到了客户端机器账户的 Net-NTLM Hash，然后是用户账户的 Net-NTLM Hash。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417112633161.png)

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417112702930.png)

## 中继 WPAD 身份验证

获取到的 Net-NTLM Hash 可以用来暴力破解，也可以通过 [ntlmrelayx.py](https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py) 执行 NTLM Relay，直接认证到网络中的其它服务器，如下图所示。

```bash
python ntlmrelayx.py -wh 172.26.10.134 -t smb://172.26.10.13 -smb2support --ipv6 -c whoami

# -wh 启用 WPAD 代理认证攻击, 指定代理服务器的地址 (此处为攻击者服务器的地址)
# -t 指定要 Relay 到的目标服务器
# --ipv6 同时监听 IPv4 和 IPv6 网络
# -c 指定要在目标服务器上执行的命令
```

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417131718366.png)

启动 mitm6 毒化后，ntlmrelayx.py 上成功截获客户端（172.26.10.21）的 NTLM 认证请求，并将其中继到目标服务器（172.26.10.13）。如下图所示，成功在目标服务器上执行系统命令。

![](/assets/posts/2022-03-26-relaying-wpad-authentication-using-mitm6/image-20220417131118939.png)
## Ending......

参考文献：

> https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
