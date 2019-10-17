---
title: windows样本高级静态分析之识别汇编中C代码结构三
date: 2019-10-09 17:07:21
tags: windows病毒分析
---

# 目标

通过分析代码结构来理解一个恶意样本的总体功能。

本篇主要通过分析样本了解for、while流程语句

# 分析流程

1.基础静态分析

2.基础动态分析

3.高级静态分析

# 实践过程

## 实例1

Lab06-04.exe

### 基础静态分析

导入函数

```
InternetOpenUrlA
InternetCloseHandle
InternetReadFile
InternetGetConnectedState
InternetOpenA
RegSetValueExA
RegOpenKeyExA
CreateDirectoryA
CopyFileA
DeleteFileA
GetFileType
WriteFile
```

字符串

```
http://www.practicalmalwareanalysis.com/cc.htm
Software\Microsoft\Windows\CurrentVersion\Run
C:\Temp\cc.exe
C:\Temp
Error 1.1: No Internet
Success: Internet Connection
Error 2.3: Fail to get command
Error 2.2: Fail to ReadFile
Error 2.1: Fail to OpenUrl
Internet Explorer 7.50/pma%d
Error 3.2: Not a valid command provided
Error 3.1: Could not set Registry value
Malware
Success: Parsed command is %c
```

这里和上一篇文章大同小异，主要在Internet Explorer 7.50/pma后面多了一个占位符

根据api和字符串可以判断：

1.存在联网访问http://www.practicalmalwareanalysis.com/cc.htm 网址操作并且通过字符串中的错信息可以判断可能存在解析网页来获取命令来执行

2.写注册表来是实现自启动

3.产生衍生文件C:\Temp\cc.exe

### 基础动态分析

![1570613321563](1570613321563.png)

和之前分析一样，根据不同网络状态返回打印内容，接着通过高级静态分析来看程序后续操作

###　高级静态分析

跟进main方法分析，大部分和Lab06-03.exe相同，下面主要分析不同之处

#### for循环流程

*for循环主要包括有：初始化、判断条件、条件成立后执行的语句块、语句块执行完毕后的递增或递减*

*所以在汇编指令中存在3个跳转：*

​	1.初始化完毕后跳转到判断条件

​	2.判断条件不成立引起的跳出for循环

​	3.条件成立后执行完语句块后跳到递增或递减的语句块处

![1570614369620](1570614369620.png)

可以大致将for语句分为3个语句块，**初始化语句块、循环体（条件成立）、递增或递减语句块**

![1570615439017](1570615439017.png)

这里用IDA视图来比较直观的观察for循环流程。

可以从里面的语句看到这里如果条件成立会循环1440次，并且每次还要睡眠1分钟，即这个程序在这里需要运行24小时

![1570616395253](1570616395253.png)

另外一个不同的地方就是这里会将循环次数传进这个函数，并且附加到这个代理字符串后面来访问网页文件，方便远程服务器知道大概的程序运行时间。别的功能都和上一个样本基本一致，这里不再赘述

## while循环补充

*while循环主要有：条件判断，条件成立后的循环体*

*所以while循环的汇编代码中只有两个跳转：*

​	1.条件判断失败后跳出循环体

​	2.条件成立并执行完循环体后直接跳转到条件判断处继续循环

![1570617115852](1570617115852.png)

从图中可以看出while流程就是一个头部为判断条件尾部为直接跳转指令的语句块，因为只有两个跳转所以速度比for循环快

## do-while流程补充

源代码:

```c
#include <stdio.h>

void main()
{
	int i = 0;
	scanf("%d", &i);
	do
	{
		printf("true");
		i--;
	}
	while(i>0);
}

```

这个do-while流程和while的区别只是将头部的条件判断放到了尾部，所以头部的条件跳转和尾部的直接跳转融合成了一个条件跳转。

只有一个跳转的do-while流程比while流程更快

![1570617890329](1570617890329.png)