---
title: windows样本高级静态分析之追踪恶意代码的运行
date: 2019-10-11 10:27:24
tags: windows病毒分析
---

# 引言

本片文章通过对Lab07_01.exe分析，来学习恶意代码执行其它代码的方式：

* 服务

* 线程

本片文章通过对Lab07_02.exe分析，来学习恶意代码执行其它代码的方式：

* COM组件

# 目标

# 流程

1.基础静态分析

2.基础动态分析

3.高级静态分析

# 实践过程

## 实例1

Lab07-01.exe

### 基础静态分析

从导出函数和字符串来看：

* 可能会创建服务`MalService`来长期驻留受感染机器
* 通过创建线程进行执行恶意行为
* 访问web页面 http://www.malwareanalysisbook.com

```
导入函数：
OpenSCManagerA
CreateServiceA
CreateMutexA
OpenMutexA
InternetOpenUrlA
InternetOpenA
CreateThread

字符串:
http://www.malwareanalysisbook.com
MalService
Malservice
HGL345
Internet Explorer 8.0
```

### 基本动态分析

程序运行后可以在服务列表中发现存在自动开启的`malware`服务配置了自启动来执行Lab07_01.exe文件来实现感染主机进行长期驻留

![1570763540722](1570763540722.png)

样本不断访问特定网站，如果是真实病毒就可以衍生出DDOS攻击、获取远程指令来本地执行、引流等行为 

![1570763904729](1570763904729.png)

不断创建线程

![1570764217501](1570764203074.png)

### 高级静态分析

创建互斥体防止进程多开

![1570764954615](1570764954615.png)

创建服务`malservice`，并且将服务配置为自启动和以独立进程启动

![1570765101378](1570765101378.png)

![1570765343023](1570765343023.png)

创建线程来无限循环的访问 http://www.malwareanalysisbook.com

![1570765614038](1570765614038.png)

![1570765683746](1570765683746.png)

### 小结

至此基本分析完毕，本次分析主要学习跟踪服务、线程来追踪恶意行为。

并学习到几个小知识点：

* 查看服务信息：
  * 可以通过`sc qc <serviceName>`查看服务配置信息，有配置注释；
  * 通过注册表可以看到没注释的服务配置；
  * 可以通过管理器看GUI界面的配置信息
* 线程执行其他代码
  * 将需要被执行代码的地址以第三个参数传入`createThread`函数里

## 实例2

Lab07-02.exe

### 基础静态分析

样本使用COM组件来访问网页

```
导入函数：
OleInitialize
CoCreateInstance
OleUninitialize

字符串：
http://www.malwareanalysisbook.com/ad.html
```

### 基础动态分析

样本启动IE浏览器访问网站

![1570779563387](1570779563387.png)

### 高级静态分析

初始化、创建COM对象，返回一个接口指针地址，但是IDA并未识别出接口和类型

![1570779829935](1570779829935.png)

我们根据riid接口标识符的全局唯一标识符goole，查到IWebBrowser2接口，然后Structures->Insert->IWebBrowser2Vtbl手动添加这个接口对应的函数表结构体然后可以手动T键将对应偏移转成符号

![1570781361337](1570781361337.png)

执行IWebBrowser2接口的Navigate方法来打开指定网页

![1570782255715](1570782255715.png)

### 小结

本例初步学习使用客户端COM组件的样本并且COM对象启动的程序以它自己的独立进程执行。

# 知识库

## COM组件

* 概念：接口标准，让不同组件在不知道对反接口规范的前提下可以进行调用

* 架构：c/s

* 使用：

  1. 初始化：使用COM库函数之前，必须至少调用一次OleInitialize或者OleInitializeEx

  2. 创建COM对象：通过CLSID(类型标识符)和IID(接口标识符)的全局唯一标识符来创建并访问COM对象
  3. 调用COM对象功能：通过函数指针表来调用函数。第二步返回一个接口指针地址（结构体指针），这个结构体的第一个值指向的就是函数指针表，第一个函数在偏移为0处，占4个字节，所以第二个数在0x04处依次类推

* 恶意代码应用：
   * 客户端：恶意代码通过创建COM对象，使用COM功能来增加分析难度，并且使用COM对象来执行恶意行为可以避免溯源到样本本身
   * 服务端：实现一个COM服务器来让其他应用使用，如BHO。识别方式：必须导出DllCanUnloadNow、DllGetClassObject、DllRegisterServer、DllUnregisterServer、DllInstall

* 查看COM服务器配置：
  * 注册表：HKEY_LOCAL_MACHINE\SOFTWARE\Classes\\CLSID\\{<CLSID>}、HKEY_CURRENT_USER\Software\Classes\CLSID\\{<CLSID>}

* 配置：
  * 存在LocalServer32项的COM类以他自己独立进程进行加载
  * 存在InprocServer32项的COM类在被调用的时候以DLL方式被加载进COM客户端可执行文件的进程空间中