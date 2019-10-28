---
title: windows样本分析之高级静态分析
date: 2019-09-08 17:28:58
tags: windows病毒分析
---

# 目标

1.鉴定黑白

2.详细静态分析，根据基础静态分析判定的结果，来详细分析样本的行为

# 原理

通过IDA阅读反汇编和伪代码，分析样本行为

# 实践过程

Lab05-01.dll

## 基础静态分析

### VT检测

* 黑样本

58/68检出率，判定为黑样本。

* 后门

根据VT上众多扫描引擎的病毒名，判断为后门样本

![1567935334458](1567935334458.png)

鉴定黑白后，进行对样本恶意行为进行进一步分析

### 信息收集

| 信息类型 | 内容                     |
| :------- | :----------------------- |
| 时间戳   | Mon Jun 09 20:49:29 2008 |
| 文件类型 | 32位GUI型DLL文件         |
| 壳特征   | 未加壳                   |

从收集到的信息上看，是一款比较老的DLL恶意文件

### 简单行为分析

1. 监控登陆窗口，记录登陆用户名密码

   根据导入表函数：`OpenDesktopA、SetThreadDesktop等`和字符串表中的`Winlogon`，在线搜索发现相关API和字符可以实现这样的功能

2. 枚举盘符

   `GetLogicalDrives、GetDriveTypeA`，根据这些API可以知道

3. 获取计算机信息

   `GetVersionExA、GetComputerNameA`

4. 创建服务，修改服务等操作

   `CreateServiceA、RegisterServiceCtrlHandlerA、StartServiceA等`

5. 文件操作，遍历、复制、删除等

   `WriteFile、CopyFileA、MoveFileExA、DeleteFileA、FindNextFileA FindFirstFileA`

6. Socket连接

   `recv、send、connect、ntohs、htons`

7. DLL注入

   `CreateToolhelp32Snapshot、Process32First、Process32Next、VirtualAllocEx、WriteProcessMemory、CreateRemoteThread`

8. 命令执行

   `WinExec、Sleep`

9. 注册表

   * 设置IE浏览器路径`SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE`
   * 服务配置`SYSTEM\CurrentControlSet\Services\`等
   * 获取设备信息`HARDWARE\DEVICEMAP\VIDEO`

10. 反虚拟机

    `Found Virtual Machine,Install Cancel.`

11. HTTP、FTP

    ```
    anonymous
    FTP://
    ftp://
    Content-Length:
    HTTP/1.1 5
    HTTP/1.1 3
    HTTP/1.1 4
    Expires: 0
    Cache-Control: no-cache, must-revalidate
    Pragma: no-cache
    Connection: Keep-Alive
    User-Agent: Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.1)
    Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*
    Host: 
     HTTP/1.1
    GET 
    HTTP://
    http://
    ```

12. 命令参数

    ```
    -warn
    -erro
    -stop
    -shutdown
    -reboot
    attrib -a -r -s -h "%s"
    rundll32.exe %s,StartEXS %s:%s
    ```

13. 衍生文件

    `.\vmselfdel.bat`

### 小结

简单从导入表和字符串表中粗略概括以上恶意行为，下面用IDA对照上面的信息，详细分析

## 高级静态分析

这里我们大概看一下，简单从导入表和导出表来看他的行为

1. 入口位置：DllMain

IDA直接识别出入口位置，并用其最重要的功能之一的F5大法来查看伪代码。如果使用rundll32.exe启动这个DLL文件，就会从这里开始执行。

很明显从下面API可以看出这里有创建多条线程的操作

![1569061539297](1569061539297.png)

2.导入表

直接定位关键函数。

跟踪关键函数 RegisterServiceCtrlHandlerA，接着用交叉引用和F5大法就可以跟到打开服务的行为

![1569063452557](1569063452557.png)

![1569063583364](1569063583364.png)

3.字符串表

根据可以的网络访问字符串，再结合跟进去后看见的socket连接行为，很明显是后门访问获取特定指令来进行HTTP请求

![1569063786988](1569063786988.png)

![1569063832785](1569063832785.png)

4.导出表

根据符号信息可以初步判断是一些安装卸载服务和其他一些行为的操作。

![1569063945987](1569063945987.png)

跟进InstallSA导出函数发现存在反虚拟机行为。

![1569064212775](1569064212775.png)

![1569064134683](1569064134683.png)

### 小结

这个简单分析初步探索一下静态逆向过程。很明显这个过程如果对Windows API不熟的话需要不断的查询,当然我们的关注点应该更专注于恶意行为会用到的API。