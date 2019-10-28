---
title: inline-hook
date: 2019-09-08 17:28:58
tags: Android Hook
---

# 引言

本片文章主要学习Android平台的Inline-Hook来配合ptrace注入实现简单的游戏破解，了解游戏破解相关的安全技术。



# 概述

下面通过一张经典的inline hook流程图，做个大致介绍。

主要通过修改一条汇编指令，让指令流程跳转到我们设计好的桩函数处，执行完我们的桩函数后紧接着执行我们修改的哪条汇编指令，紧接着经过一个跳转指令返回原来的指令流程里继续程序的正常执行。

![](165921tz43a3sm4vi2s4s4.png)

# 内联算法

1. 先构造我们的桩函数，主要进行以下操作：
   * 寄存器的备份，为第三步继续执行原指令做准备
   * 跳转到用户自定义函数的指令
   * 寄存器还原操作
   * 跳转到构造好的原指令函数
2. 构造原指令函数，这个原指令函数主要是执行将要被修改的汇编指令，并跳转到程序正常的执行流程中
3. 指令覆盖操作。使用跳转指令覆盖原指令



# 代码实现

**Ihook.h**：头文件，声明了hook过程中用到的一些功能函数和宏定义

```c++
#include <stdio.h>
#include <Android/log.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#ifndef BYTE
#define BYTE unsigned char
#endif

#define OPCODEMAXLEN 8      //inline hook所需要的opcodes最大长度

#define LOG_TAG "GSLab"
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);

/** shellcode里用到的参数、变量*/
extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s; //根函数地址
extern unsigned long _old_function_addr_s;  //原指令地址

//hook点信息
typedef struct tagINLINEHOOKINFO{
    void *pHookAddr;                //hook的地址
    void *pStubShellCodeAddr;            //跳过去的shellcode stub的地址
    void (*onCallBack)(struct pt_regs *);  
    //回调函数，跳转过去的函数地址
    void ** ppOldFuncAddr;             //shellcode 中存放old function的地址
    BYTE szbyBackupOpcodes[OPCODEMAXLEN];    //原来的opcodes
} INLINE_HOOK_INFO;

//更高内存页属性
bool ChangePageProperty(void *pAddress, size_t size);

//获取模块基址
extern void * GetModuleBaseAddr(pid_t pid, char* pszModuleName);

//初始化ARM指令集的hook信息结构体
bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook);

//构建桩函数
bool BuildStub(INLINE_HOOK_INFO* pstInlineHook);

//构建跳转代码
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);

//构建原指令的函数
bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook);

//重写hook点的原指令，使其跳转到桩函数处
bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook);

//HOOK的总流程
extern bool HookArm(INLINE_HOOK_INFO* pstInlineHook);
```

**Ihook.c**:HookArm函数，主要的Hook模块。我们先将整个hook流程串起来，再去补全4个功能函数的代码

```c
#include "Ihook.h"


bool HookArm(INLINE_HOOK_INFO* pstInlineHook)
{
    //hook结果
    bool bRet = false;

    while(1)
    {
        //判断是否传入Hook点信息的结构体
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break
        }

        /* 初始化hook点的信息，如原指令地址、将要执行的用户自定义函数*/
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }

        /* 1. 构造桩函数*/
        if(BuildStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }

        /* 2. 构造原指令函数，执行被覆盖指令并跳转回原始指令流程*/
        if(BuildOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }

        /* 3. 改写原指令为跳转指令，跳转到桩函数处*/
        if(RebuildHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}
```

**hook.c**:InitArmHookInfo函数，保存原指令的opcode

```c
/**
 *  初始化hook点信息，保存原指令的opcode
 *
 *  @param  pstInlineHook hook点相关信息的结构体
 *  @return 初始化是否成功
 */
bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, 8);
    return bRet;
}
```

**hook.c**:BuildStub函数，第一步构造桩函数，这里我们用shellcode来构造。

* 我们申请一块内存并且将内存属性改成可执行，将shellcode拷进去，shellcode的起始地址就是桩函数的地址，将这个地址存进hook点结构体中
* 还有将shellcode中存有原指令函数地址的变量留空，并且将该变量的内存地址存放进hook点结构体中，以便在构造原指令函数的时候，用原指令函数的地址将shellcode中的这个变量填充
* 从hook点结构体中获取用户自定义函数的地址给shellcode中的_hookstub_function_addr_s变量赋值

```c
/**
 *  修改页属性，改成可读可写可执行
 *  @param   pAddress   需要修改属性起始地址
 *  @param   size       需要修改页属性的长度，byte为单位
 *  @return  bool       修改是否成功
 */
bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;

    if(pAddress == NULL)
    {
        LOGI("change page property error.");
        return bRet;
    }
    //计算包含的页数、对齐起始地址
    unsigned long ulPageSize = sysconf(_SC_PAGESIZE);
    int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
    //页对齐，把小于4096的位数(前12位)都置0，只取大于4096的位数且其值必然是4096的整数倍
    //并且这个值必然小于等于参数pAddress
    unsigned long ulNewPageStartAddress = (unsigned long)(pAddress) & ~(ulPageSize - 1);
    
    long lPageCount = (size / ulPageSize) + 1;
    int iRet = mprotect((const void *)(ulNewPageStartAddress), lPageCount*ulPageSize , iProtect);
    if(iRet == -1)
    {
        LOGI("mprotect error:%s", strerror(errno));
        return bRet;
    }
    return true;
}

/**
 *  1. 构造桩函数。这里的桩函数我们主要在shellcode中实现
 *      * 保存寄存器的值
 *      * 跳转到用户自定义函数callback
 *      * 寄存器还原操作
 *      * 跳转到构造好的原指令函数中
 *
 *  @param  pstInlineHook hook点相关信息的结构体
 *  @return inlinehook桩是否构造成功
 */
bool BuildStub(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //导入数据段中shellcdoe的开始、结束地址，为用户自定义函数callback和将要构造的原指令函数保留的地址
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;
        
        //malloc一块内存，将shellcode拷贝进去并修改这块内存为可执行权限
        //并且更新hook点结构体的数据，让结构体中保存有桩函数(shellcode)的地址和一个变量的地址，这个变量存放着原指令函数的地址，并且这个变量在构造原指令函数的时候才会存进真实的地址
        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        void *pNewShellCode = malloc(sShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }
        
        //从参数中获取用户自定义函数callback的地址，并填充到shellcode中
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        //桩函数(shellcode)的地址
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;
        //变量地址，存放原指令函数地址的变量
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
        bRet = true;
        break;
    }
    
    return bRet;
}
```

**ihookstub.s**:shellcode：具体做到以下桩函数的功能

* 保存寄存器值
* 跳转执行用户自定义的函数callback
* 还原寄存器的值
* 跳转执行原指令函数

```assembly
.global _shellcode_start_s
.global _shellcode_end_s
.global _hookstub_function_addr_s
.global _old_function_addr_s

.data

_shellcode_start_s:
    push    {r0, r1, r2, r3}				;取push完r0-r4的sp，后面在这个基础上进行更改，所以我们需要保存的r13的值就是sp+0x10
    mrs     r0, cpsr						;将CPSR寄存器内容读出到R0
    str     r0, [sp, #0xC]					;将cpsr保存到sp+#0xC的位置
    str     r14, [sp, #8]   				;将r14(lr)保存到sp+8
    add     r14, sp, #0x10					;sp+0x10的值存放进r14
    str     r14, [sp, #4]    				;保存寄存器r13的值到sp+4的位置
    pop     {r0}               				;sp+4
    push    {r0-r12}           				;保存寄存器的值。sp+4-0x34=sp-0x30，将r0-r12压栈
    mov     r0, sp							;将栈顶位置放入r0，作为参数传入_hookstub_function_addr_s函数内
    ldr     r3, _hookstub_function_addr_s
    blx     r3								;调用用户自定义函数callback
    ldr     r0, [sp, #0x3C]					;sp-0x30+0x3c=sp+0xc,刚好是之前保存cpsr的栈地址
    msr     cpsr, r0						;恢复cpsr
    ldmfd   sp!, {r0-r12}       			;恢复r0-r12的寄存器的值，sp-0x30+0x34=sp+4
    ldr     r14, [sp, #4]					;恢复r14的值。sp+4+4=sp+8刚好是保存了r14寄存器的值
    ldr     sp, [r13]						;恢复寄存器r13的值(r13=sp+4)刚好是之前保存的r13的值
    ldr     pc, _old_function_addr_s		;跳转回即将构造的原指令函数处
    
_hookstub_function_addr_s:
.word 0xffffffff

_old_function_addr_s:
.word 0xffffffff

_shellcode_end_s:

.end
```



**hook.c**:BuildOldFunction第二步主要构造原指令函数，用到了一个构造跳转指令的功能

```c
/**
 *  (ARM)修改指定位置的指令为跳转到另一个指定位置的跳转指令。
 *  @param  pCurAddress      当前地址，要构造跳转指令的位置
 *  @param  pJumpAddress     目的地址，要从当前位置跳过去的地址
 *  @return                  跳转指令是否构造成功
 */
bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    bool bRet = false;

    while(1)
    {
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break
        }
        
        //LDR PC, [PC, #-4]的机器码是0xE51FF004
        BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};
        //LDR PC, [PC, #-4]指令执行时，PC的值刚好是PC+8的位置，也就是PC-4=pc+8-4=pc+4的值就是下一条指令的值
        //我们用地址代替指令值，实现修改PC寄存器执行到指定地址的功能
        memcpy(szLdrPCOpcodes + 4, &pJumpAddress, 4);
        //修改指定位置的指令
        memcpy(pCurAddress, szLdrPCOpcodes, 8);
        cacheflush(*((uint32_t*)pCurAddress), 8, 0);

        bRet = true;
        break;
    }

    return bRet;
}

/**
 *  2.构造原指令函数。
 *      * 执行原指令
 *      * 跳转到原始指令流程中，即原指令的下一条指令处
 *  出了上面两个功能我们还需要将shellcode中的原指令函数地址进行填充，承接上面的流程
 *
 *  @param  pstInlineHook hook点相关信息的结构体
 *  @return 原指令函数是否构造成功
 */
bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //8字节原指令，8字节原指令的下一条指令
        void * pNewEntryForOldFunction = malloc(16);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }

        if(ChangePageProperty(pNewEntryForOldFunction, 16) == false)
        {
            LOGI("change new entry page property fail.");
            break;    
        }

        //拷贝原指令到内存块中
        memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        //拷贝跳转指令到内存块中
        if(BuildArmJumpCode(pNewEntryForOldFunction + 8, pstInlineHook->pHookAddr + 8) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }

        //填充shellcode里stub的回调地址
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;

        bRet = true;
        break;
    }

    return bRet;
}
```



**hook.c**:RebuildHookTarget函数。最后一步，覆盖原指令(8字节长度，2条指令)，使其跳转到我们构造好的桩函数(shellcode)中去

```c
/**
 * 3. 覆盖HOOK点的指令，跳转到桩函数的位置
 * @param  pstInlineHook inlinehook信息
 * @return 原地跳转指令是否构造成功
 */
bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }

        //修改原位置的页属性，保证可写
        if(ChangePageProperty(pstInlineHook->pHookAddr, 8) == false)
        {
            LOGI("change page property error.");
            break;
        }
        
        //覆盖原指令为跳转指令
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }

        bRet = true;
        break;
    }

    return bRet;
}
```



# 应用实例

这里我们利用一个测试App，他的Native层写了一个这样的功能，如果我们不对其进行修改，他将5分钟后才会返回一个"Enough. You Win!"，现在我们的目的就是利用内联hook修改这个uiTimeCounter属性的值使其立刻输出"Enough. You Win!"

```cpp
static unsigned int uiTimeCounter = 0x1;

//该函数，根据uiTimeCounter全局变量，返回两种结果字符串
//大于30则返回成功提示，否则返回等待提示
JNIEXPORT jstring JNICALL Java_com_example_gslab_ibored_MainActivity_UpdateResult
        (JNIEnv *pJniEnv, jclass Jclass)
{
    unsigned  int uiLocalVar = 1;

    uiTimeCounter += uiLocalVar;

    if(uiTimeCounter > 300)
    {
        //win
        return pJniEnv->NewStringUTF("Enough. You Win!");
    }
    else
    {
        //wait
        return pJniEnv->NewStringUTF("Just Wait.");
    }
}
```

## 实现过程

### 第一步

找到我们需要修改的点。这里我们用IDA进行寻找。从下面代码中可以看到这里我们使用的r0寄存器进行判断，如果小于等于300就输出"just wait",所以我们需要Hook的点就是这个判断语句处，将r0改成大于300即可

![](1560307847662.png)

计算出HOOK点相对模块的偏移地址。上图可以知道HOOK点的地址为AF86399A，基地址可以crtl+s，找到代码段的开始地址，在经过相减(AF88C49C-AF859000)得到偏移值为0x3349c

![](1560307804978.png)



### 第二步

根据需要修改的点，利用我们最开始写的hook功能，来编写代码修改这个点

```cpp
#include <vector>

extern "C"
{
    #include "Ihook.h"
}

//声明函数在加载库时被调用,也是hook的主函数
void ModifyIBored() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //管理HOOK点

/**
 *  对外inline hook接口，负责管理inline hook信息
 *  @param  pHookAddr     要hook的地址
 *  @param  onCallBack    要插入的回调函数
 *  @return inlinehook是否设置成功（已经设置过，重复设置返回false）
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct pt_regs *))
{
    bool bRet = false;

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }
    
    //填写hook点位置和用户自定义回调函数
    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if(HookArm(pstInlineHook) == false)
    {
        LOGI("HookArm fail.");
        delete pstInlineHook;
        return bRet;
    }

    gs_vecInlineHookInfo.push_back(pstInlineHook);
    return true;
}

/**
 *  用户自定义的回调函数，修改r0寄存器大于300
 */
void EvilHookStubFunctionForIBored(pt_regs *regs)
{
    LOGI("In Evil Hook Stub.");
    regs->uregs[0] = 0x333;
}

/**
 *  1.Hook入口
 */
void ModifyIBored()
{
    LOGI("In IHook's ModifyIBored.");
    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "libnative-lib.so");
    if(pModuleBaseAddr == 0)
    {
        LOGI("get module base error.");
        return;
    }

    //模块基址加上HOOK点的偏移地址就是HOOK点在内存中的位置
    uint32_t uiHookAddr = (uint32_t)pModuleBaseAddr + 0x3349c;
    LOGI("uiHookAddr is %X", uiHookAddr);
    
    //HOOK函数
    InlineHook((void*)(uiHookAddr), EvilHookStubFunctionForIBored);
}
```

上面的hook代码中用到了获取基地址的函数pModuleBaseAddr，所以我们需要在**hook.c**文件中补充这个函数

```c
/*
 * 通过/proc/$pid/maps，获取模块基址
 * @param   pid                 模块所在进程pid，如果访问自身进程，可填小余0的值，如-1
 * @param   pszModuleName       模块名字
 * @return  void*               模块基址，错误则返回0
 */
void * GetModuleBaseAddr(pid_t pid, char* pszModuleName)
{
        FILE *pFileMaps = NULL;
        unsigned long ulBaseValue = 0;
        char szMapFilePath[256] = {0};
        char szFileLineBuffer[1024] = {0};

        //pid判断，确定maps文件
        if (pid < 0)
        {
            snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
        }
        else
        {
            snprintf(szMapFilePath, sizeof(szMapFilePath),  "/proc/%d/maps", pid);
        }

        pFileMaps = fopen(szMapFilePath, "r");
        if (NULL == pFileMaps)
        {
            return (void *)ulBaseValue;
        }

        //循环遍历maps文件，找到相应模块，截取地址信息
        while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL)
        {
            if (strstr(szFileLineBuffer, pszModuleName))
            {
                char *pszModuleAddress = strtok(szFileLineBuffer, "-");
                if (pszModuleAddress)
                {
                    ulBaseValue = strtoul(pszModuleAddress, NULL, 16);

                    if (ulBaseValue == 0x8000)
                    {
                        ulBaseValue = 0;
                    }
                    break;
                }
            }
        }

        fclose(pFileMaps);
        return (void *)ulBaseValue;
}
```



### 第三步

针对上面的代码我们进行编译工作

**编译HOOK功能模块的静态库**：jni/InlineHook/Android.mk

同目录下有IHook.c、ihookstub.s、IHook.h、Andropid.mk

* LOCAL_ARM_MODE：编译后的指令都是4字节长度的arm指令集
* LOCAL_CPPFLAGS：如果编译cpp文件，需要给编译器传递一组选项

```
LOCAL_PATH := $(call my-dir)  


include $(CLEAR_VARS)

LOCAL_CPPFLAGS +=  -g -O0
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := IHook
LOCAL_SRC_FILES := IHook.c ihookstub.s
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

include $(BUILD_STATIC_LIBRARY)
```



**hook主模块**：jni/Interface/Android.mk

同目录下有InlineHook.cpp、Android.mk

* LOCAL_STATIC_LIBRARIES：引用我们上面编译的静态库
* LOCAL_C_INCLUDES：此选项添加目录到include搜索路径中

```
LOCAL_PATH := $(call my-dir)  

include $(CLEAR_VARS)

LOCAL_CPPFLAGS +=  -g -O0
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := InlineHook
LOCAL_STATIC_LIBRARIES:= IHook
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../InlineHook
LOCAL_SRC_FILES := InlineHook.cpp
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

include $(BUILD_SHARED_LIBRARY)
```



**编译所有目录下的文件**：jni/Android.mk

```
include $(call all-subdir-makefiles)
```

jni/Application.mk

* APP_STL：选择C++标准库
* APP_CPPFLAGS：标记所有编译的cpp文件，启用C++异常

```
APP_ABI := armeabi-v7a
APP_STL := c++_static
APP_CPPFLAGS += -fexceptions
```



**开始编译**：在jni目录下执行`ndk-build`命令,即可在jni同目录下的libs目录中生成so共享库



> 这里需要注意，我们上面写的hook模块是基于arm指令集的，所以我们测试用的项目也要声明使用arm指令集，如果是cmake，在app目录下的build.gradle文件中设置如下
>
> ```
> defaultConfig {
> 	...
> 	 externalNativeBuild {
>             cmake {
>                 ...
>                 arguments "-DANDROID_ARM_MODE=arm"
>             }
>         }
> }
> ```



### 第四步

hook之后，我们出了成功提早输出这句话后，我们这边的比较指令也被改成相应跳转指令

![](1560308215956.png)

![](1560308396552.png)



# 小结

【1】先构造好我们的装函数，再覆盖原指令进行跳转。防止我们先进行原指令覆盖后，程序执行到这里但是我们的桩函数还没构造好而引发的异常

【2】覆盖指令的是否为什幺覆盖2条，这是因为我们构造跳转指令的时候，需要两条指令的长度

【3】一定需要注意指令集的确定，不同指令集我们跳转函数LDR PC,[RC, #-4]的指令是不同的，需要覆盖的长度也是不同的

# 参考

【书籍】游戏安全-手游安全技术入门