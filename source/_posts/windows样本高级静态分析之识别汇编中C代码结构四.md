---
title: windows样本高级静态分析之识别汇编中C代码结构四
date: 2019-10-10 11:02:59
tags: windows病毒分析
---

# 引言

通过将一条条指令组合成原始的数据类型完成汇编指令到高级语言结构

# 目标

掌握数组、链表、结构体等数据类型的汇编指令。

# 流程

1. 编写源代码，生成对应程序
2. 返汇编程序
3. 分析汇编代码，总结数据类型的特点
4. 小结

# 实践过程

## 数组类型

* 源代码

```c
#include <stdio.h>

void main()
{
	int arr[5];
	arr[0] = 1;
	arr[1] = 2;
	for(int i=2; i<5; i++)
	{
		arr[i] = i;
	}
}
```

* 汇编代码

![1570677323050](1570677323050.png)

* 数据类型特点

选区一块内存区域存放数组内容，这里选取的是栈上内存块并且从`ebp+arr`开始，然后将数据填充到这块内存里。

1. 一块内存上的每个元素长度一致

* 小结

```assembly
call    ds:__imp__malloc
...
mov     [ebp+eax*4+arr], ecx
```

给一段内存地址赋长度相同的值，看到类似上面这种指令的时候就可以浮现出一个对应数据类型的数组

## 结构体

* 源代码

```c
#include <stdio.h>
#include <stdlib.h>

struct mystruct
{
	int x[5];
	char y;
};

struct mystruct *test;

void main()
{
	test = (struct mystruct *)malloc(sizeof(struct mystruct));
	for(int i=0; i<5; i++)
	{
		test->x[i]= i;
	}
	test->y = 'a';
}
```

* 汇编代码

![1570679670515](1570679670515.png)

* 特点

malloc出一块内存，然后给这块内存赋不同类型的数据

1. 一个内存上每个元素不全一致

* 小结

```assembly
mov     ecx, ?test@@3PAUmystruct@@A ;
mov     edx, [ebp+var_2C]
mov     [ecx+eax*4], edx
...
mov     eax, ?test@@3PAUmystruct@@A ; mystruct * test
mov     byte ptr [eax+14h], 'a'
```

malloc得到一块内存后，给其赋不同长度或不同类型的数据

## 链表

* 源代码

```c
#include <stdio.h>
#include <stdlib.h>

struct node
{
	int x;
	struct node * next;
};

typedef node pnode;

void main()
{
	pnode * curr, * head;
	int i;
	head = NULL;
	for(i = 1; i<=3; i++)
	{
		curr = (pnode *)malloc(sizeof(pnode));
		curr->x = i;
		curr->next = head;
		head = curr;
	}
}
```

* 汇编代码

![1570680406808](1570680406808.png)

* 特点

malloc一块内存，给这块内存内赋任意元素数据和`一个内存地址`，这个内存地址指向另一块相同类型的内存。

1. 一个内存块里必须存在一个元素指向另一个相同类型的内存块

