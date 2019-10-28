---
title: ptrace注入(shellcode)
date: 2019-09-08 17:28:58
tags: Android注入
---

# 引言

继ptrace注入之dlopen/dlsym注入第三方so库到远程进程中后，本次探索的是shellcode 的注入



# 概述

shellcode注入是通过将dlopen/dlsym库函数的操作放在了shellcode中，注入函数只是通过对远程进程进行内存申请，接着修改shellcode 中有关dlopen/dlsym库函数使用到的参数，然后直接将shellcode注入到远程进程申请的空间中，通过修改pc寄存器的方式来执行shellcode 处的代码



# 注入算法

【1】在shellcode中编写好dlopen、dlsym函数的调用来加载so库和执行函数，但是需要将参数地址、函数地址、寄存器地址先随便填写一些值为我们真实的地址保留

【2】附加远程进程、保存此刻寄存器的数据，为后面恢复远程进程的继续执行准备

【3】申请内存空间，选好shellcode存放的具体位置，准备存放shellcode和参数数据

【4】计算本地库函数对应到远程进程中的库函数地址，填充到shellcdoe中的参数中去。计算好库函数参数、寄存器存值相对shellcode起始位置的偏移再加上远程进程中shellcode存放的起始位置，得到的结果就是远程进程的内存空间中这些参数存放的位置，将这些地址填充到shellcode的参数中去

【5】设置寄存器的值来让执行库函数

【6】恢复寄存器的值让远程进程继续正常执行



# 代码实现

**shellcode代码**

```assembly
@定义了存放库函数参数地址、函数地址、寄存器地址的全局变量，为的是在注入代码中可以获取变量地址并传入数据
.global _dlopen_addr_s
.global _dlopen_param1_s
.global _dlopen_param2_s

.global _dlsym_addr_s
.global _dlsym_param2_s

.global _dlclose_addr_s

.global _inject_start_s
.global _inject_end_s

.global _inject_function_param_s

.global _saved_cpsr_s
.global _saved_r0_pc_s

.data

_inject_start_s:
	@ debug loop
3:
	@sub r1, r1, #0
	@B 3b

	@ dlopen，加载第三方so库
	ldr r1, _dlopen_param2_s
	ldr r0, _dlopen_param1_s
	ldr r3, _dlopen_addr_s
	blx r3
	subs r4, r0, #0
	beq	2f

	@dlsym，根据提供的库函数名称，搜索so库中的函数位置
	ldr r1, _dlsym_param2_s
	ldr r3, _dlsym_addr_s
	blx r3
	subs r3, r0, #0
	beq 1f

	@call 调用注入库中的函数
	ldr r0, _inject_function_param_s
	blx r3
	subs r0, r0, #0
	beq 2f

1:
	@dlclose，如果没有在被使用就卸载动态库
	mov r0, r4
	ldr r3, _dlclose_addr_s
	blx r3

2:
	@restore context，恢复成注入前的指令执行状态
	ldr r1, _saved_cpsr_s
	msr cpsr_cf, r1
	ldr sp, _saved_r0_pc_s
	ldmfd sp, {r0-pc}

_dlopen_addr_s:
.word 0x11111111

_dlopen_param1_s:
.word 0x11111111

_dlopen_param2_s:
.word 0x2

_dlsym_addr_s:
.word 0x11111111

_dlsym_param2_s:
.word 0x11111111

_dlclose_addr_s:
.word 0x11111111

_inject_function_param_s:
.word 0x11111111

_saved_cpsr_s:
.word 0x11111111

_saved_r0_pc_s:
.word 0x11111111

_inject_end_s:

.space 0x400, 0

.end
```



**注入函数**inject_remote_process_shellcode，可以放在inject_remote_process函数的下面

```c
//宏定义了一个远程进程计算
#define REMOTE_ADDR( addr, local_base, remote_base ) ( (uint32_t)(addr) + (uint32_t)(remote_base) - (uint32_t)(local_base) ) 


/*************************************************
  Description:    通过shellcode方式ptrace注入so模块到远程进程中
  Input:          pid表示远程进程的ID，LibPath为被远程注入的so模块路径，FunctionName为远程注入的模块后调用的函数
				  FuncParameter指向被远程调用函数的参数（若传递字符串，需要先将字符串写入到远程进程空间中），NumParameter为参数的个数
  Return:         返回0表示注入成功，返回-1表示失败
*************************************************/ 
	int iRet = -1;
	struct pt_regs CurrentRegs, OriginalRegs;  // CurrentRegs表示远程进程中当前的寄存器值，OriginalRegs存储注入前的寄存器值，方便恢复
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;   // 远程进程中需要调用函数的地址
	void *RemoteMapMemoryAddr, *RemoteModuleAddr, *RemoteModuleFuncAddr; // RemoteMapMemoryAddr为远程进程空间中映射的内存基址，RemoteModuleAddr为远程注入的so模块加载基址，RemoteModuleFuncAddr为注入模块中需要调用的函数地址
	long parameters[10];  
	int i;
	uint32_t code_length;

	uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_start_ptr, *local_code_start_ptr, *local_code_end_ptr;
	
	//导入shellcode中的全局变量
	extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, _saved_cpsr_s, _saved_r0_pc_s;
	
	// Attach远程进程
	if (ptrace_attach(pid) == -1)
		return iRet;
	
	// 获取远程进程的寄存器值，保存下来为恢复做准备
	if (ptrace_getregs(pid, &CurrentRegs) == -1)
	{
		ptrace_detach(pid);
		return iRet;
	}
	// 保存远程进程空间中当前的上下文寄存器环境
	memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)); 

	LOGD("ARM_r0:0x%lx, ARM_r1:0x%lx, ARM_r2:0x%lx, ARM_r3:0x%lx, ARM_r4:0x%lx, ARM_r5:0x%lx, ARM_r6:0x%lx, ARM_r7:0x%lx, ARM_r8:0x%lx, ARM_r9:0x%lx, ARM_r10:0x%lx, ARM_ip:0x%lx, ARM_sp:0x%lx, ARM_lr:0x%lx, ARM_pc:0x%lx", \
		CurrentRegs.ARM_r0, CurrentRegs.ARM_r1, CurrentRegs.ARM_r2, CurrentRegs.ARM_r3, CurrentRegs.ARM_r4, CurrentRegs.ARM_r5, CurrentRegs.ARM_r6, CurrentRegs.ARM_r7, CurrentRegs.ARM_r8, CurrentRegs.ARM_r9, CurrentRegs.ARM_r10, CurrentRegs.ARM_ip, CurrentRegs.ARM_sp, CurrentRegs.ARM_lr, CurrentRegs.ARM_pc);

	// 获取mmap函数在远程进程中的地址
	mmap_addr = GetRemoteFuncAddr(pid, libc_path, (void *)mmap);
	LOGD("mmap RemoteFuncAddr:0x%lx", (long)mmap_addr);

	// 设置mmap的参数
	// void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);
    parameters[0] = 0;  // 设置为NULL表示让系统自动选择分配内存的地址    
    parameters[1] = 0x4000; // 映射内存的大小    
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // 表示映射内存区域可读可写可执行   
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射    
    parameters[4] = 0; //  若需要映射文件到内存中，则为文件的fd  
    parameters[5] = 0; //文件映射偏移量 	

	// 调用远程进程的mmap函数，建立远程进程的内存映射
	if (ptrace_call(pid, (long)mmap_addr, parameters, 6, &CurrentRegs) == -1)
	{
		LOGD("Call Remote mmap Func Failed");
		ptrace_detach(pid);
		return iRet;
	}

	// 获取mmap函数执行后的返回值，也就是内存映射的起始地址
	RemoteMapMemoryAddr = (void *)ptrace_getret(&CurrentRegs);
	LOGD("Remote Process Map Memory Addr:0x%lx", (long)RemoteMapMemoryAddr);
	
	// 分别获取dlopen、dlsym、dlclose等函数的地址
	dlopen_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlopen);
	dlsym_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlsym);
	dlclose_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlclose);
	dlerror_addr = GetRemoteFuncAddr(pid, linker_path, (void *)dlerror);
	
	LOGD("dlopen RemoteFuncAddr:0x%lx", (long)dlopen_addr);
	LOGD("dlsym RemoteFuncAddr:0x%lx", (long)dlsym_addr);
	LOGD("dlclose RemoteFuncAddr:0x%lx", (long)dlclose_addr);
	LOGD("dlerror RemoteFuncAddr:0x%lx", (long)dlerror_addr);
	
	//将这几个库函数所对应的远程进程中的函数地址写到汇编代码中的变量中
	_dlopen_addr_s = (uint32_t)dlopen_addr;
	_dlsym_addr_s = (uint32_t)dlsym_addr;
	_dlclose_addr_s = (uint32_t)dlclose_addr;

	remote_code_start_ptr = RemoteMapMemoryAddr + 0x1000; // 远程进程中存放shellcode代码的起始地址，这里需要将起始位置向后偏移一些位置，否则会因为sp指针的设定而引发段错误(signal 11)
	local_code_start_ptr = (uint8_t *)&_inject_start_s;     // 本地进程中shellcode的起始地址
	local_code_end_ptr = (uint8_t *)&_inject_end_s;          // 本地进程中shellcode的结束地址
	LOGD("Inject Code Start:0x%x, end:0x%x", (int)local_code_start_ptr, (int)local_code_end_ptr);

	// 计算shellcode中一些变量的存放起始地址,这些地址是我们一会将参数数据传入得地址，稍微向后加一些偏移量(MAX_PATH)没有关系的,但是代码长度和数据偏移总长度不要超过我们注入注入时的数据长度
	code_length = (uint32_t)&_inject_end_s - (uint32_t)&_inject_start_s;
	LOGD("Inject Code length: %d", code_length);
	dlopen_param1_ptr = local_code_start_ptr + code_length;// + 0x20;
	LOGD("local dlopen first parameter addr is 0x%x", dlopen_param1_ptr);
	dlsym_param2_ptr = dlopen_param1_ptr + MAX_PATH;
	LOGD("local dlsym second parameter addr is 0x%x", dlsym_param2_ptr);
	saved_r0_pc_ptr = dlsym_param2_ptr + MAX_PATH;
	inject_param_ptr = saved_r0_pc_ptr + MAX_PATH;

	// 写入dlopen的参数LibPath到我们上一步算好的本地地址，然后再计算出远程进程中
	strcpy( dlopen_param1_ptr, LibPath );
	_dlopen_param1_s = REMOTE_ADDR( dlopen_param1_ptr, local_code_start_ptr, remote_code_start_ptr );
	LOGD("Remote dlopen first parameter addr is 0x%x", _dlopen_param1_s);

	// 写入dlsym的第二个参数，需要调用的函数名称
	strcpy( dlsym_param2_ptr, FunctionName );
	_dlsym_param2_s = REMOTE_ADDR( dlsym_param2_ptr, local_code_start_ptr, remote_code_start_ptr );
	LOGD("Remote dlsym second parameter addr is 0x%x", _dlsym_param2_s);

	//保存cpsr寄存器
	_saved_cpsr_s = OriginalRegs.ARM_cpsr;

	//保存r0-pc寄存器
	memcpy( saved_r0_pc_ptr, &(OriginalRegs.ARM_r0), 16 * 4 ); // r0 ~ r15
	_saved_r0_pc_s = REMOTE_ADDR( saved_r0_pc_ptr, local_code_start_ptr, remote_code_start_ptr );
	LOGD("Remote r0-pc registers addr is 0x%x", _saved_r0_pc_s);

	memcpy( inject_param_ptr, FuncParameter, NumParameter );
	_inject_function_param_s = REMOTE_ADDR( inject_param_ptr, local_code_start_ptr, remote_code_start_ptr );
	LOGD("My fuction parameter addr is 0x%x", _inject_function_param_s);
	
	//将我们的shellcode还有参数数据都写入到远程进程的内存空间中去
	ptrace_writedata( pid, remote_code_start_ptr, local_code_start_ptr, 0x400 );
	LOGD("wriate data complete");

	//设置寄存器开始执行shellcode
	memcpy( &CurrentRegs, &OriginalRegs, sizeof(CurrentRegs) );
	LOGD("cpoy register addr complete");
	//如果将sp堆栈指针指向shellcode代码的位置，就需要将shellcode位置向后申请的内存空间的后面推移，否则sp可能会指向申请的内存空的前面的位置，造成段错误(signal 11)
	//CurrentRegs.ARM_sp = (long)remote_code_start_ptr;
	CurrentRegs.ARM_pc = (long)remote_code_start_ptr;
	ptrace_setregs( pid, &CurrentRegs );
	LOGD("set register addr complete");
	ptrace_detach( pid );
	LOGD("injected complete");
	return 0;	
}
```



# 小结

【1】在计算库函数的偏移地址时，需要记住的是同一个库中的库函数它在不同进程中的偏移是相同的

【2】我们计算远程进程中参数地址的时候，我们是根据相对shellcode初始位置偏移来算的

【3】如果注释掉堆栈指针sp指向shellcode地址的指令，我们就可以不用将shellcode在申请的内存空间中往后移动，因为不用担心sp指针肯能会指向我们我们未申请的内存区域



