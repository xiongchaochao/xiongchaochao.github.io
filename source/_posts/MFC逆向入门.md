---
title: CrackMe：寻找核心函数
date: 2019-12-23 18:24:10
tags: CTF
---

# 引言

通过简单的MFC程序来入门MFC逆向。而我们的目的是寻找核心逻辑函数，主要是下面方法

* **消息映射表**：当用户点击程序上的按钮后会产生对应的消息，通过消息映射表来查找处理函数进行处理，这个处理函数可以自己实现
* **函数重写**：有些默认按钮的消息处理函数可以通过重写来进行自定义处理过程

下面首先先介绍两种方法，然后通过例子来使用，本篇主要粗浅了解一哈怎么分析MFC程序，并不是最简解题思路（字符串大法）

# 定位消息映射表

在`CWnd::OnWndMsg`函数里执行`GetMessageMap`来获取消息映射表的偏移

```c++
BOOL CWnd::OnWndMsg(UINT message, WPARAM wParam, LPARAM lParam, LRESULT* pResult)
{
     // ....
     const AFX_MSGMAP* pMessageMap; 
     pMessageMap = GetMessageMap();
     // ....
          if ((lpEntry = AfxFindMessageEntry(pMessageMap->lpEntries, message, 0, 0)) != NULL)
     // ...
  
}
```

从IDA中获取该导入函数的调用地址，动态调试断进函数中，这里就是GetMessageMap函数调用的地方，执行完获取消息映射表的地址

```assembly
mov edx,dword ptr ds:[eax+30]           |
mov ecx,edi                             | ecx:"|4@", edi:"|4@"
call edx                                |
```

可以看在.rdata区段中，进入sub_4014C0可以看到CDialog::messageMap函数的调用，证明找到正确位置

![1577176300576](1577176300576.png)

`Shift+F1`->`Insert`导入消息映射表的结构体，然后选中导入的结构体右键同步到IDA中`Synchronize to ida`

```
struct AFX_MSGMAP_ENTRY
{
	UINT nMessage;
	UINT nCode;
	UINT nID;
	UINT nLastID;
	UINT_PTR nSig;
	void (*pfn)(void);
};
 
struct AFX_MSGMAP
{
  const AFX_MSGMAP *(__stdcall *pfnGetBaseMap)();
  const AFX_MSGMAP_ENTRY *lpEntries;
};
```

然后将光标选中消息映射表的地址，`Alt+Q`修改数据类型为`AFX_MSGMAP`，然后根据`AFX_MSGMAP`中的第二个属性offset stru_41BAA8来将unk_41BAA8位置修改为`AFX_MSGMAP_ENTRY`，因为这个类型是数组所以我们右键该类型选择`Array..`自动识别为数组，失败就手动转一下，将数据修改为一下格式.

![1577178142367](1577178142367.png)

可以看到如果下结果，0x111是按钮被按下的消息号，而后面数字对应的就是控件ID，最后的函数地址就是消息处理函数

![1577178415604](1577178415604.png)

# 消息处理函数重写

但是如果出现一种情况，我们在消息映射表中未能发现我们要寻找控件的消息处理函数。如下图，没有0x111这个按钮被按下时发送的消息号

![1577177094807](1577177094807.png)

这个时候我们就要考虑另外一种情况，没有消息映射就会使用库默认的消息处理函数来进行处理，IDOK对应的是CDialog::OnOk或者子类的处理函数，依次类推

![1577180705026](1577180705026.png)

这里我们用到的程序我们根据ID确定是CDialog::OnOk或者子类的处理函数

![1577181149337](1577181149337.png)

直接IDA随意搜索一个CDialog虚函数，定位到.rdata段的虚表，在交叉引用的过程中我们发现存在多个虚表

![1577181316609](1577181316609.png)

我们在下面的子类虚表中，进去之后我们根据两个虚表不同的识别结果，可以看到子类中重写了父类的CDialog::OnOk()以至于IDA未识别出对应符号，进去之后发现了我们需要找到的核心函数

![image-20191225104258747](image-20191225104258747.png)

![1577181561940](1577181561940.png)

# 实例

看雪CTF签到试题

![1577183324923](1577183324923.png)

## 确认控件ID

点击控件，控件ID：1

![1577183367684](1577183367684.png)

## 定位消息映射表

IDA中寻找CWnd::OnWndMsg函数位置，00401E10

![1577183667200](1577183667200.png)

动态调试步入该函数内部，找到调用[eax+30]位置，动态获取返回结果403308

![1577184690209](1577184690209.png)

导入结构体`AFX_MSGMAP_ENTRY`、`AFX_MSGMAP`并修改该处地址，未发现0x111消息号，也就是消息映射表中没有我们要找的控件被按下处理的消息

![1577184966469](1577184966469.png)

## 消息处理函数重写

上面方法未能找到我们需要的狠心函数。接着用另一种方法判断是否是消息处理函数的重写这种情况。找根据ID号1对应的消息处理函数OnOk，我们首先通过离OnOk比较近的CDialog::DoModal交叉引用到虚表处，可以看到存在两个虚表

![image-20191225104053407](image-20191225104053407.png)

在第二个虚表处可以看到OnOk未被识别出

![image-20191225104159791](image-20191225104159791.png)

进去之后找到我们需要的核心处理过程

![image-20191225104920945](image-20191225104920945.png)

加密非常简单，直接亮出脚本得到flag

```python
a = r'goluck!'
b = []
c = r'cuk!ogl'
for i in a:
    index = c.index(i)
    b.append(chr(index + 48))
print("".join(b))
```

# 参考

【1】[**浅析MFC逆向（Basic MFC Reversing）**](https://www.pediy.com/kssd/pediy12/120058.html)

【2】[使用IDA定位基于MFC的CrackMe的按钮函数-----实践篇（一）](https://blog.csdn.net/SilverMagic/article/details/40622413)