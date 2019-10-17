---
title: windows样本高级静态分析之追踪恶意代码的运行二
date: 2019-10-12 12:17:11
tags: windows病毒分析
---

# 概述

本片文章通过对Lab07_03.exe分析，来学习恶意代码执行其它代码的方式：

* 文件映射（CreateFileMappingA、MapViewOfFile：CreateFileMappingA将文件映射进内存返回一个句柄，进而由MapViewOfFile来根据句柄获取这个文件在内存中的地址）
  * 修改正常文件来植入恶意DLL
* DLL文件
  * 保存恶意代码并通过别的方式来注入到正常进程中

本片文章通过对Lab07_03.dll分析，来学习恶意代码执行其它代码的方式：

* 创建进程(CreateProcessA)
  * 通过第二个参数lpCommandLine来启动恶意PE文件
  * 通过配置第九个参数lpStartupInfo的输入、输出、错入流为socket句柄来创建远程shell

本篇分析的样本通过修改所有EXE文件的导入表来将系统DLL替换成病毒DLL进行驻留。

# 目标

分析恶意代码的执行

# 分析流程

1.基础静态分析

2.基础动态分析

3.高级静态分析

# 实践过程

## 实例

Lab07-03.exe

Lab07-03.dll

### 基础静态分析

#### Lab07-03.exe

1.遍历整个C盘搜索所有后缀为.exe的PE文件、映射指定文件到内存里

2.将Lab07-03.dll修改成C:\windows\system32\kerne132.dll，但是并没有加载这个DLL的操作

```
导入函数：
MapViewOfFile
CreateFileMappingA
CreateFileA
FindClose
FindNextFileA
FindFirstFileA
CopyFileA

字符串
.exe
C:\*
C:\windows\system32\kerne132.dll
C:\Windows\System32\Kernel32.dll
kerne132.dll
kernel32.dll
Kernel32.
Lab07-03.dll
WARNING_THIS_WILL_DESTROY_YOUR_MACHINE
```

#### Lab07-03.dll

1.创建互斥体防止进程多开

2.socket连接127.26.152.13可能会获取命令并执行

```
导入函数：
CreateMutexA
OpenMutexA
23 (socket)
115 (WSAStartup)
11 (inet_addr)
4 (connect)
19 (send)
22 (shutdown)
16 (recv)
3 (closesocket)
9 (htons)
Sleep
CreateProcessA

字符串：
exec
127.26.152.13
```

### 基础动态分析

没有抓取到明显动态特征

### 高级静态分析

#### Lab07-03.exe



样本需要参数"WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"

![](1570862035124.png)

sub_401040和下面进行复杂的逻辑运算，如非必须分析直接跳过，暂时我们先跳过继续向下面分析

![](1570863509375.png)

结尾处将"Lab07-03.dll"复制到了"C:\\windows\\system32\\kerne132.dll"实现隐藏行为，接着跟如sub_4011E0

![1570863758532](1570863758532.png)

遍历C盘所有文件，对以".exe"后缀的文件执行sub_4010A0操作，下面我们跟进这个函数

![](1570865815365.png)

文件偏移为0xF处的并非任何一个属性的开始位置，感觉应该不太对，我们将鼠标光标放在0xF处进入汇编视图

![1570866258637](1570866258637.png)

上面的伪代码不正确，真实伪代码是"result + 0x3C"，在IMAGE_DOS_HEADER结构体中指向NtHeader的地址

![1570866383083](1570866383083.png)

解析PE文件，判断NT头是否为0x4550，然后把导入表的虚拟地址传入sub_401040函数，因为这个是复杂的逻辑运算，我们先看后面的调用。

判断经过两次sub_401040运算后的结果字符串是否为kernel32.dll，如果是就在内存中替换成kerne132.dll，也就是说上面主要是解析导入表。	

![](1570867416209.png)

根据导入表指针指向的结构体来看，偏移为"0xC"的元素刚好就是导入库的符号名称并且该结构体总长度为0x14

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
union {
DWORD Characteristics;
DWORD OriginalFirstThunk;//指向输入名称表的表（INT）的RVA
};
DWORD TimeDateStamp;
DWORD ForwarderChain;
DWORD Name;//指向导入映像文件的名称
DWORD FirstThunk;//指向输入地址表的表（IAT）的RVA

} IMAGE_IMPORT_DESCRIPTOR;
```

根据偏移值我们发现这里其实是一个偏移导入表获取符号名称进行匹配的操作，也就是sub_401040返回的就是第一个参数。

最后遍历所有exe文件将其映射到内存中，将存在kernel32.dll的所有EXE文件内的kernel32.dll符号全部替换成kerne132.dll

![1570869811288](1570869811288.png)

#### Lab07-03.dll

1.创建互斥体防止进程多开

2.创建socket发送消息和接收指令

​	2.1.如果接收sleep就睡眠60s

​	2.2如果接收exec就创建进程，但是我们会发现CommandLine的交叉引用并没有发现有哪里给他赋值

![1570872609152](1570872609152.png)

我们双击进入CommandLine的栈位置,我们会发现命令会被存放到0xFFB处并且接收命令的buf就在他上面，也就是我们接收的命令足够长就会填充到CommandLine处。

所以我们应该输入的命令是："exec <完整的文件路径>"，这样我们就可以启动任意位置出的可执行文件

![1570872999165](1570872999165.png)