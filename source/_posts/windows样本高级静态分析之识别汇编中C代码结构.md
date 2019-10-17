---
title: windows样本高级静态分析之识别汇编中C代码结构
date: 2019-09-30 17:41:06
tags:
---

# 目标

通过分析代码结构来理解一个恶意样本的总体功能

# 分析流程

1.基础静态分析

2.基础动态分析

3.高级静态分析

# 实践过程

## 实例1

Lab06-01.exe

### 基础静态分析

```
导入表：wininet.dll、kernel32.net
导入函数：InternetGetConnectedState
字符串值：Error 1.1: No Internet、Success: Internet Connection
```

从导入库、导入函数、以及字符串可以看出该样本存在检测网络状态的功能

### 基础动态分析

![1569839422847](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569839422847.png)

运行样本后，通过联网和断网两种情景样本打印出不同输出，基本可以确定存在网络状态检测功能

### 高级静态分析

通过一个if-else语句，根据不同网络状态返回值来打印不同的字符串，并且根据基础动态分析的反馈可以判断sub_40105F函数为printf函数

![1569839837640](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569839837640.png)

## 实例2

### 基础静态分析

导入函数

```
InternetOpenUrlA
InternetCloseHandle
InternetReadFile
InternetGetConnectedState
InternetOpenA
```

字符串

```
http://www.practicalmalwareanalysis.com/cc.htm
Error 1.1: No Internet
Success: Internet Connection
Error 2.3: Fail to get command
Error 2.2: Fail to ReadFile
Error 2.1: Fail to OpenUrl
Internet Explorer 7.5/pma
Success: Parsed command is %c
```

从导入函数和字符串可以看出，这个样本应该对网页发起请求，并且可能存在解析网页来获取命令的操作

### 基础动态分析

![1569843562281](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569843562281.png)

根据返回的信息，是访问url失败，手动在浏览器访问该网页缺失已经实效

### 高级静态分析

![1569844087764](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569844087764.png)

跟进main函数分析代码得到只有跟进上面的两个if语句内部，即满足这两个if语句的成立条件才可以打印出`'Success: Parsed command is %c'`,而如果不满足条件就会退出，接着我们跟进sub_401000函数，分析如果满足第一个if语句的跳转条件

![1569844446178](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569844446178.png)

直接跟进sub_401000函数，和实例1的功能一样，需要联网才可以返回为1，即满足一个if成立条件

![1569844888712](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569844888712.png)

直接跟进第二函数sub_401040，分析得到需要打开http://www.practicalmalwareanalysis.com/cc.htm网页进入下一层if语句，接着读取到网页文件才可以进入最后一层if语句，在最后满足读取文件内容以`<!--`开头就可以将网页的第5个字符返回。

最终满足两个if语句的成立条件，打印出`Success: Parsed command is %c`

#### 数组修复

![1569846201564](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569846201564.png)

根据MSDN上的函数介绍，我们知道 InternetReadFile函数是向lpBuffer这个数组内写入数据的，大小有dwNumberOfBytesToRead决定

在分析最后一个条件判断时，ida并没有识别出这个函数的数组长度，所以后面三个比较都是用变量var_20F等来表示的。

![1569846469149](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569846469149.png)

手动修复数组大小为512字节

![1569846510907](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569846510907.png)

![1569846588106](D:\Blog\source\_posts\windows样本高级静态分析之识别汇编中C代码结构\1569846588106.png)

这样IDA就可以识别出这个函数的其他参数并且给其命名，相应的伪代码也可以识别出位数组的元素了