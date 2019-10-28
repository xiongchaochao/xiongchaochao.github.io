---
title: windows样本高级动态分析四
date: 2019-10-24 10:23:08
tags: windows病毒分析
---

# 目标

通过样本继续熟悉WinDbg工具的使用和内核恶意代码的行为

* 驱动加载过程
* Rootkit技术之挂钩SSDT表
* 蓝屏分析
* 清除带有驱动的恶意代码

# 流程

1. 基础静态分析
2. 高级静态动态结合分析

# 实践过程

## 实例1

Lab10-02.exe

### 基础静态分析

#### Lab10-02.exe

1.根据"CreateServiceA"和"ntoskrnl.exe"以及sys后缀的文件名，得出该样本涉及到了内核行为

2.从"LoadResource"和资源中的PE文件看来，样本存在另一个执行模块在资源节里

```
导入函数：
CreateServiceA
StartServiceA
FindResourceA
LoadResource

资源：
存在一个PE文件

字符串：
C:\Windows\System32\Mlwx486.sys
ntoskrnl.exe
SIOCTL.sys
```

#### 衍生文件

这是一个驱动文件，只有一些目录搜索、字符串操作的行为

```
subsystem: Native(不需要子系统，一般是驱动程序)

导入表：
NtQueryDirectoryFile
MmGetSystemRoutineAddress
RtlInitUnicodeString
RtlCompareMemory

version:
文件类型： device-driver
原始文件名： SIOCTL.sys
```

### 高级动态静态结合分析

"Lab10-02.exe"将资源中的文件写入到"C:\\Windows\\System32\\Mlwx486.sys"位置

![1571885683174](D:\Blog\source\_posts\windows样本高级动态分析四\1571885465714.png)

接着创建驱动服务"486 WS Driver"并且将上一步中的"C:\\Windows\\System32\\Mlwx486.sys"文件作为驱动服务的二进制可执行文件，然后开启服务。

![1571885810114](D:\Blog\source\_posts\windows样本高级动态分析四\1571885810114.png)

从上面的分析可以看出"Lab10-02.exe"文件的主要作用就是将dump出驱动文件，接着创建驱动服务来启动执行驱动。接下来开始分析驱动文件。

首先是加载驱动时调用的"DriverEntry"函数：

1. 获取"NtQueryDirectoryFile"内核函数地址以及"KeServiceDescriptorTable"SSDT(系统服务描述表)的地址
2. 遍历SSDT匹配出"NtQueryDirectoryFile"内核函数的项
3. 用sub_10486替换SSDT表中"NtQueryDirectoryFile"内核函数的项，实现对其挂钩

下面分析挂钩后的函数"sub_10486"的具体行为

![1571887352709](D:\Blog\source\_posts\windows样本高级动态分析四\1571887352709.png)

当触发hook函数时，调用正常的"NtQueryDirectoryFile"

1. 接着判断"FileInformationClass"参数值是否等于3，即"FILE_BOTH_DIR_INFORMATION"属性，作用是获取目录下所有文件和文件夹的信息，详细信息以多个结构体"_FILE_BOTH_DIR_INFORMATION"返回到"FileInformation"参数指定的指针中，作用于打开文件夹后获取文件夹中每个文件以及文件夹信息并展示出来，否则就退出
2. "NtQueryDirectoryFile"返回值大于等于0，需要函数执行成功，否则退出
3. 当只要求目录中的单个条目时则退出

![1571913079191](D:\Blog\source\_posts\windows样本高级动态分析四\1571913079191.png)

接着，从结尾跳转看出这是一个do-while流程。

do的代码块：

* 第一步：将bl置0

* 第二步：比较"esi+5Eh"地址存放的值也就是文件名和Unicode字符串"Mlwx"是否存在相同的8字节数据

  * 如果存在：bl+1，接着第2层if语句判断edi是否为0（初始为0），如果为0，跳出第2层if语句，执行到loc_104F4，如果为0，将"esi"处的值也就是下一个"FILE_BOTH_DIR_INFORMATION"结构体的偏移值赋给eax，接着开始第3层if语句判断，判断eax的值也就是下一个"FILE_BOTH_DIR_INFORMATION"结构体偏移是否为0，也就是是否存在下一个结构体，如果存在就将这个结构体地址和edi地址的值相加并存放到edi指向的地址，如果不存在就将edi指向的值置0

    ```c
    if ( RtlCompareMemory([esi + 5e], "Mlwx", 8u) == 8 )
    {
       bl++;
       if ( edi )
       {
          if ([esi])
              [edi] += [esi];
          else
              [edi]  = 0;
       }
    }
    ```

  * 如果不存在，执行到loc_104F4

    ```c
    if([esi] == 0)
    	break
    if(bl == 0)
        edi = esi
    esi += [esi]
    ```

总结一哈上面的行为：使用do-while循环来遍历文件夹里的所有文件以及文件夹的"FILE_BOTH_DIR_INFORMATION"，查询结构体来判断文件名中是否存在"Mlwx"字符串，如果存在，将上一个文件结构体的"NextEntryOffset"值加上当前文件结构体中的"NextEntryOffset"值，实现了上一个文件的"NextEntryOffset"值直接跳过当前文件而指向了下一个文件的结构体的操作。然后如果没有下一个结构体了就退出，如果还有就将继续上面的行为

![1571969680342](D:\Blog\source\_posts\windows样本高级动态分析四\1571969680342.png)

下面我们动态跟一下这个具体执行流程

"bu $iment(Mlwx486)"根据驱动程序名称给其入口位置下延迟断点，然后在主机执行"g"，让虚拟机运行起来并且执行"Lab10-02.exe"，这样在启动驱动的时候就会命中断点。

#### 蓝屏引出的CR0

当我们单步一直到替换SSDT表的"NtQueryDirectoryFile"函数的时候出现了蓝屏。

从图中可以看出应该是我们的驱动文件访问写数据到只读区域而引起的

![1571987016100](D:\Blog\source\_posts\windows样本高级动态分析四\1571987016100.png)

我们去虚拟机中用windbg打开dump出的文件分析一下。如果没有下载符号，在执行"analyze -v"分析蓝屏时会去下载需要的符号文件.

导入dump文件后我们会发现出错位置位于"Mlwx486+760"，正好就是IDA中的"0x10760"处的SSDT表项替换指令，到这里我们可以得出蓝屏原因，SSDT表有只读保护，我们替换时触发异常导致蓝屏，所以我们需要找到方法解除这种保护。（还有一点需要注意：删除注册表中驱动服务后，重启机器才可以重新执行安装驱动的操作）

![1571987993709](D:\Blog\source\_posts\windows样本高级动态分析四\1571987993709.png)

我们找到参考【2】中这篇文章，发现只要将CR0寄存器的WP设置为0就可以写入数据了，下面我们用WinDbg实施一哈

1. 首先运行到替换SSDT表的指令处

2. 我们"rM 80"查看CR0寄存器的值，我们只修改WP位就行，也就是"r @cr0=8000003b"即可，然后执行完替换指令后，再将只读保护修改回来，不然可能会引发不可预料错误

   ```
   2: kd> rM 80
   cr0=8001003b cr2=00160000 cr3=00185000
   ```

3. 验证替换结果，"dd dwo KeServiceDescriptorTable L100"，查看SSDT表项内容，可以明显看到异于其他地址的项，也确实是样本中被替换的函数位置

   ![1571989179669](D:\Blog\source\_posts\windows样本高级动态分析四\1571989179669.png)

### 小结

该样本虽然HOOK成功了，但是在win7 32位虚拟机中并不能实现隐藏文件的恶意行为，在调试的过程中，打开文件夹等操作并不一定可以触发HOOK函数，而即使触发了，并且完成了替换结构体"FILE_BOTH_DIR_INFORMATION"也依然可以看见目录下的文件，在网上搜索后发现应该是需要HOOK "ZwQueryDirectoryFile"函数来实现隐藏，有环境的同学可以自己编译代码来测试一下。

清除主机上的样本：删除服务的注册表项即可，如果遇到"LEGACY_486_WS_DRIVER"项，可以借助**psexec**工具为regedit工具提升到system权限即可："psexec -i -d -s c:\windows\regedit.exe"

## 实例2

Lab10-03.exe

Lab10-03.sys

### 基础静态分析

#### Lab10-03.exe

1. 创建驱动服务实现对设备的读写操作
2. 存在网页链接但是没有网络API，所以初步断定为COM组件实现的联网行为

```
导入函数：
CreateServiceA
StartServiceA
DeviceIoControl
OleUninitialize
CoCreateInstance

字符串：
\\.\ProcHelper
C:\Windows\System32\Lab10-03.sys
http://www.malwareanalysisbook.com/ad.html
```

#### Lab10-03.sys

创建设备对象"\Device\ProcHelper"以及设备对象的符号链接链接"\DosDevices\ProcHelper"供内核中使用，`\\.\ProcHelper`供用户态应用程序访问

```
导入函数：
IofCompleteRequest
IoDeleteDevice
IoCreateSymbolicLink
IoCreateDevice

字符串：
\DosDevices\ProcHelper
\Device\ProcHelper
```

### 高级动态静态结合分析

首先是Lab10-03.exe，为"C:\\Windows\\System32\\Lab10-03.sys"驱动文件创建驱动服务"Process Helper"，开启服务来加载驱动，随后关闭该服务。并且该加载驱动只限于首次创建，后续由于没有删除服务所以不会在这里开启该服务

![1572232933190](D:\Blog\source\_posts\windows样本高级动态分析四\1572232933190.png)

这一步很奇怪，打开设备对象的符号链接，进行I/O操作但是并没有输入输出数据，这里暂时留个疑问，接着看下去

![1572235321340](D:\Blog\source\_posts\windows样本高级动态分析四\1572235321340.png)

创建"IWebBrowser2"接口的COM对象，接着访问偏移为0x2C位置的函数，并传入参数"http://www.malwareanalysisbook.com/ad.html"，所以我们这里根据引入结构体来识别偏移位置的函数为"IWebBrowser2Vtbl.Navigate"，启用IE浏览器来访问该网页

![1572235780631](D:\Blog\source\_posts\windows样本高级动态分析四\1572235780631.png)

接着我们看一下驱动文件具体做了哪些行为。

1. 创建设备对象"\\Device\\ProcHelper"

2. 给驱动对象添加MajorFunction主函数表中赋了3个函数(偏移为：0、2、E)以及卸载函数的赋值，这一步可以根据"dt nt!_DRIVER_OBJECT"来查看驱动对象结构图，发现主函数表位置刚好是偏移0x38处，卸载函数位置刚好是0x34位置处。

   并且我们查询"wdm.h"中这个头文件可以知道：偏移为0的函数对应IRP_MJ_CREATE请求，2对应IRP_MJ_CLOSE，0xE对应IRP_MJ_DEVICE_CONTROL

3. 创建驱动对象的符号链接来让用户空间的程序可以访问到设备对象

4. 删除设备对象

![1572237121512](D:\Blog\source\_posts\windows样本高级动态分析四\1572237121512.png)

```
2: kd> dt nt!_DRIVER_OBJECT
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x004 DeviceObject     : Ptr32 _DEVICE_OBJECT
   +0x008 Flags            : Uint4B
   +0x00c DriverStart      : Ptr32 Void
   +0x010 DriverSize       : Uint4B
   +0x014 DriverSection    : Ptr32 Void
   +0x018 DriverExtension  : Ptr32 _DRIVER_EXTENSION
   +0x01c DriverName       : _UNICODE_STRING
   +0x024 HardwareDatabase : Ptr32 _UNICODE_STRING
   +0x028 FastIoDispatch   : Ptr32 _FAST_IO_DISPATCH
   +0x02c DriverInit       : Ptr32     long 
   +0x030 DriverStartIo    : Ptr32     void 
   +0x034 DriverUnload     : Ptr32     void 
   +0x038 MajorFunction    : [28] Ptr32     long 
```

wdm.h头文件

```c
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
....
#define IRP_MJ_DEVICE_CONTROL           0x0e
```

这里我们分析不同IRP请求对应的处理函数内容。

首先是IRP_MJ_CREATE和IRP_MJ_CLOSE请求，这里只是告诉系统已经完成了处理请求的操作，属于正常行为

![1572246726664](D:\Blog\source\_posts\windows样本高级动态分析四\1572246726664.png)

IRP_MJ_DEVICE_CONTROL，当用户模式下DeviceIoControl调用或者内核模式ZwDeviceIoControlFile调用时发送请求包时，有该函数进行处理，结合上面一个很奇怪的DeviceIoControl调用，我们可以断定和这里的处理函数有关。

调用IoGetCurrentProcess获取一个指针指向当前进程，内部实际上是调用的PsGetCurrentProcess ，最终这个返回的指针是一个指向一个未公布的结构体*EPROCESS*，具体可以参考【4】



![1572247768559](D:\Blog\source\_posts\windows样本高级动态分析四\1572247768559.png)

```

```

# 补充知识

* **MajorFunction**(驱动对象结构体)：指向一个主函数表，这个表存放着所有用户态应用程序调用内核态驱动程序所有的函数地址，表中每个索引代表不同的请求，这些请求在wdm.h文件中定义，并且以**IRP_MJ_**开头，例如用户态应用程序调用DeviceIoControl函数对应函数表中的IRP_MJ_DEVICE_CONTROL
* **DeviceIoControl**(驱动对象结构体)：当恶意代码获取到设备对象的句柄时，通过该函数向设备发送控制代码，让设备执行相应操作。还有一些其他的用户态函数可以执行相同的操作，如CreateFile、ReadFile、WriteFile
* **设备对象：**内核驱动中，所有设备都是由`\\Device`开头，例如：C盘就是被命名为*\Device\HarddiskVolume1*，也可以不指定设备名称，系统会自动分配一个数字作为设备名如“*/Device/00000001*”
* **设备对象的符号链接：**内核中需要创建符号链接来让用户态应用程序访问内核中的设备对象。内核中的符号链接以*\??*(或者*\DosDevices*)开头；而在用户模式下，以`\\.`开头

# 参考

【1】https://unordered.org/timelines/588f9f9c06c00000

【2】[SSDT-HOOK保护进程](https://bbs.pediy.com/thread-250832.htm)

【3】[.driverbase-驱动对象、设备对象、DriverEntry、IoCreateDevice、符号链接、DriverUnLoad、WDM](https://blog.csdn.net/hgy413/article/details/17737517)

【4】[IoGetCurrentProcess 反彙編分析](https://www.twblogs.net/a/5b8731fb2b71775d1cd67d34)

