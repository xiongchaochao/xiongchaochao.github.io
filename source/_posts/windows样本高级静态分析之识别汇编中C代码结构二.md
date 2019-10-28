---
title: windows样本高级静态分析之识别汇编中C代码结构二
date: 2019-10-08 18:31:26
tags: windows病毒分析
---

# 目标

通过分析代码结构来理解一个恶意样本的总体功能。

本篇主要通过分析样本了解switch语句

# 分析流程

1.基础静态分析

2.基础动态分析

3.高级静态分析

# 实践过程

## 实例1

Lab06-03.exe

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
Internet Explorer 7.5/pma
Error 3.2: Not a valid command provided
Error 3.1: Could not set Registry value
Malware
Success: Parsed command is %c
```

根据api和字符串可以判断：

1.存在联网访问http://www.practicalmalwareanalysis.com/cc.htm 网址操作并且通过字符串中的错信息可以判断可能存在解析网页来获取命令来执行

2.写注册表来是实现自启动

3.产生衍生文件C:\Temp\cc.exe

### 基础动态分析

![1570531441363](1570531441363.png)

和之前分析一样，根据不同网络状态返回打印内容，接着通过高级静态分析来看程序后续操作

### 高级静态分析

直接跟如main函数进行分析

![1570531826979](1570531826979.png)

*cmp指令，脑子里立刻浮现一个if-else语句流程图，将跳转后的语句和紧跟跳转指令后的指令填入对应的if和else语句块中。*

判断条件：sub_401000函数返回结果，即联网状态

if(条件成立)：调用sub_401040函数获取返回结果，如果返回结果不为0则太跳转到loc_40123C，所以接下来分析sub_401040

else(条件不成立)：eax置0，并且跳转到main函数结尾

![1570534305691](1570534305691.png)

sub_401040: 第一层也就是最外层的if语句判断是否可以打开http://www.practicalmalwareanalysis.com/cc.htm，如果可以打开则条件成立，进入嵌套的第二层if语句，判断是否可以读取该网页文件，如果可以则进入嵌套的第三层if语句，判断读取的内容是否以`<!--`开头，如果条件成立则将接下来的数据赋给al并跳转返回。

我们假设满足条件：可以访问到网页文件并且网页文件以`<!--`开头，返回数据后，我们进入loc_40123C主要分析sub_401130函数：

##### switch语句（if+跳转表）

![1570534823520](1570534823520.png)

根据上一步从网页中获取的数据来得到对应的edx值，从而根据找到跳转表对应的位置进行跳转并执行相应代码。

这里有：

* 创建目录
* 复制当前程序到C:\\Temp\\cc.exe
* 删除C:\\Temp\\cc.exe
* 设置C:\\Temp\\cc.exe对应的开启自启动注册表键值Malware

#### 小结

分析到这里基本完毕。

主要恶意行为就是通过从网页中获取的指令来执行对样本的隐藏、删除、自启动以及创建目录的操作。

## switch补充

上面的实例中介绍到了switch的一种跳转表的跳转形式，下面补充一种纯用if语句进行的跳转：

真实代码

```C
#include <stdio.h>


void main()
{
	int i = 0;
	scanf("%d", &i);
	switch(i)
	{
	case 0:
		printf("a");
		break;
	case 1:
		printf("b");
		break;
	case 2:
		printf("c");
		break;
	default:
		break;
	}
}
```

汇编：

![1570536333060](1570536333060.png)

cmp + jz + jmp实现的switch流程