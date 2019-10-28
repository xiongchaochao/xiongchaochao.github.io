---
title: TX脱壳
date: 2019-09-08 17:28:58
tags: Android脱壳
---

# 概述

本片文章描述一次完整的脱壳历程，从java层到Native层



# 流程概述

## Java层

1. java层找到库函数的入口位置
2. 过掉java层的反调试(解决方法在Native层：动态在isDebuggerConnected下断点)



## Native层

1. 绕过Anti IDA
2. 双层解密JNI_OnLoad
3. 动态调试JNI_OnLoad，得到注册的本地方法的具体位置
4. 分析load方法找到Dex动态解密的地方并dump



# 详细过程

这次脱壳用的测试机是Dalvik虚拟机4.4版本，所以底层用的libdvm.so库文件。

## 壳特征

有过壳经验的分析人员可以从安装包的特征文件和lib下的libshellxxx.so中看出是TX加固过的壳

![](1561555704027.png)



## java层

### 实锤加壳

在manifest中的入口类LoadingActivity是找不到的

```xml
<application android:theme="@style/AppTheme_Main" android:label="@string/app_name" android:icon="@mipmap/icon_launcher" android:name="com.tencent.StubShell.TxAppEntry" android:allowBackup="false" android:vmSafeMode="true" android:largeHeap="true" android:supportsRtl="true" android:extractNativeLibs="true" android:networkSecurityConfig="@xml/network_security_config" android:appComponentFactory="androidx.core.app.CoreComponentFactory">

...........
<activity android:name="com.warmcar.nf.x.ui.activity.main.LoadingActivity" android:launchMode="singleTask">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

```



### 初探attachBaseContext

既然入口类被隐藏了，我们根据调用关系找到启动入口类的地方，即Application这个类，我们主要需要关注的是attachBaseContext方法，这个在onCreate方法之前执行的



### 弃用jadx

这个方法首先调用e(context)进行了调试检查，接着在b(this)方法中进行了一些库地址的初始化操作

接着在 d(context)方法中加载不存在的库nfix、ufix，并且调用了本地方法fixNativeResource、fixUnityResource，从名称上看应该是修复操作

接下来主要是tx的SDK崩溃信息收集模块的功能，这块可以省略，主要看最后一个a((Context) this)方法，find Usage跳转过去发现调用了e()方法和load(f)方法

```javascript

    protected void attachBaseContext(Context context) {
        super.attachBaseContext(context);
        e(context);
        SystemClassLoaderInjector.fixAndroid(context, this);
        if (b(this)) {
            d(context);
            this.k = new Handler(getMainLooper());
            String str = "3.0.0.0";
            String str2 = "900015015";
            UserStrategy userStrategy = new UserStrategy(this);
            userStrategy.setAppVersion(str);
            CrashReport.setSdkExtraData(this, str2, str);
            CrashReport.initCrashReport(this, str2, false, userStrategy);
            new Thread(new d(this)).start();
            a((Context) this);
        }
    }

private void d(Context context) {
        AssetManager assets = context.getAssets();
        String str = context.getApplicationInfo().sourceDir;
        try {
            System.loadLibrary("nfix");
            fixNativeResource(assets, str);
        } catch (Throwable th) {
        }
        try {
            System.loadLibrary("ufix");
            fixUnityResource(assets, str);
        } catch (Throwable th2) {
        }
    }

public void a(Context context) {
        e();
        load(f);
    }

```

而在jadx这里e方法并未生成相应伪代码，反汇编指令倒是没有错，为了方便分析，开启我们的jeb继续分析

![](1561596719850.png)



### 接盘侠：jeb探索首次加载so库

接续分析e();方法，根据反编译后的伪代码，可以看到这里第一次进行了so库的加载，加载shell

![](1561598371802.png)

还有一个紧跟着的本地的load方法，这个需要我们在Native层进行分析，参数是shella-3.0.0.0.so文件路径



### 寥寥几句onCreate

分析完attachBaseContext，接着分析onCreate

可以看到出了一个反调试和崩溃信息收集，我们的关注重点就在本地方法runCreate

```java
public void onCreate() {
        TxAppEntry.isDebugger(((Context)this));
        TxAppEntry.runCreate(((Context)this));
        this.sdkcrash(TxAppEntry.context);
    }

private static native void runCreate(Context arg0) {
    }
```



### 再度回顾加壳包目录

加固主要行为都在这里，可以从目录名称看出，多个反调试类

刨去没什么太紧要的类，只有一个TxReceiver类值得专注

![](1561599808358.png)

通过交叉引用，并未发现有地方注册广播来执行这里，排除静态注册，剩下只有动态注册可能，都需要Native层的分析。而且他的回调方法onReceive的内部实现是通过本地方法reciver实现的，是需要第二个关注的点

```java
public class TxReceiver extends BroadcastReceiver {
    public static String TX_RECIEVER;

    static {
        TxReceiver.TX_RECIEVER = "com.tencent.StubShell.TxReceiver";
    }

    public TxReceiver() {
        super();
    }

    public void onReceive(Context arg1, Intent arg2) {
        TxAppEntry.receiver(arg2);
    }
}
######################################################TxAppEntry.java
public static void receiver(Intent arg0) {
    TxAppEntry.reciver(arg0);
}

private static native void reciver(Intent arg0) {
}
```



### 短暂小结，再度启程

壳的分析基本到这里暂停下来

**主要分析结果**：

​	找到了唯一一个要加载的库shella3.0.0.0.so，根据分析流程继续分析native层的load、runCreate方法

**留下的疑惑**：

​	修复ufix、nfix是否得到调用

​	广播行为



## Native层

分析shella3.0.0.so，首次加载的so库



**分析目标**

1. 本地方法runCreate

2. java层修复ufix、nfix的fixNativeResource、fixUnityResource方法是否得到调用，做了哪些行为
3. 实锤广播注册，探索广播行为



### 出师未捷，对抗IDA

IDA6.8打开libshella-3.0.0.0.so弹出未识别的节格式，反编译失败，什么东西都没有！这不禁引发了我对人生的思考，是对抗反编译吗、还是对抗IDA呢？这是我需要探索的问题

![](1561635493865.png)

![](1561643354375.png)

使用010edit打开so文件，可以看到解析文件是没有问题的，但是text、init等个别节头表内的数据都被抹空了，个别节头没有，如.dynstr、.dynsym

#### 思考

【1】如果IDA根据节数据进行反汇编，这里数据都为空，确实会反编译失败，那么如何恢复这些节表呢？但是在看到参考【4】中文章的时候，根据之前使用经验得出一些想法，**IDA在识别节头失败后会去通过程序头表来进行分析**

【2】上面这种报错：**检测出不识别的section格式**导致终止反编译的行为很明显是**对抗IDA**这种反编译工具的，这也回答了上面需要探索的问题。

​	为了解决其对抗IDA行为，我们这里直接将节内数据置空或者将包含字符的节数据置0，让他识别无意义或非法的节声明，接着使用程序头来进行分析即可。最终定位到.dynsym表的s_size字段，将这个字段置0即可

![](1561691320543.png)



###  Anti不能停：JNI_OnLoad加密

过掉AntiIDA后，再次加载so文件，可以看到导出JNI_OnLoad函数已经被加密了（虚拟内存地址=0x274C），那么合理向上推导，只能在.init节或者.init_array节中

接下来的目标就是找到init、init_array节所在的地址

![](1561692877111.png)





#### 解决思路

【1】修复section节头

【2】动态调试so，通过在linker.so上下断点

![](1561637165614.png)



### section修复，觅得init_array

修复之前多个节都是置空的，还有个别节错误数据来Anti IDA

![](1561637165614.png)



通过[开源代码](https://github.com/WangYinuo/FixElfSection)对so文件进行修复后，在linux平台用readelf可以看到已经将很多节头的偏移恢复了，

![](1561642997171.png)

在ida6.8打开时，首先出现下面两个弹窗中的出现的错误，全部确认

![](1561643152043.png)

![](1561643169497.png)



我们根据觅得的init_array地址，抱着兴奋的情绪进行G跳转到0x3e84，这里切记别乱改数据类型，这里应该是**DCD**代表双字，代表的地址是0x944。

> 这里我犯了个错，由于不太熟吧，乱改数据类型，改成DCB字节型，结果转成代码后就懵了，在心灰意冷下我打开了IDA7.2，看到下面那个图，一度让我准备和IDA 6.8 say 拜拜。但是由于7.2 F5大法不管用（原因暂时未知），6.8还是很棒的，还是和它做好基友吧

![](1561714564043.png)

这里要是用IDA7.2版本，他这里会识别出init节并标记（感觉棒棒哒）

![](1561714669645.png)



### 通读伪代码，分析init_array

这里主要分析出：

* 解密算法是从0x1000开始，对0x2AB4字节数据进行解密(JNI_OnLoad地址为0x274c必然被包含在内)
* 调用JNI_OnLoad

分析出解密算法，可以自己写脚本进行解密，这里我们选择另外一种，往下看

![](1561775189715.png)



### 另辟蹊径，解密JNI_OnLoad

**思路**：so库一经加载到内存后，要处于解密后的状态才可以正常被程序调用，所以从内存中dump出shella-3.0.0.0.so文件，即完成对JNI_Onload解密的操作

> 无意之举吧，：）
>
> 当时准备通过调试获取init_array内存地址的时候没有成功，当时想着dump下so文件应该包含有解密后的节头表，后来看到一篇文章结合ELF装载知识才知道节头表并不会被装载进内存更谈不上dump下来，但是用IDA打开后的JNI_OnLoad确是解密后的

解密脚本，具体内存地址和加载进内存的段长度，需要自己调试的时候Ctrl+S自己看和计算

```c
static main()
{
    auto i,fp;
    fp = fopen("d:\\dump","wb");
    auto start = 0x75FFD000;
    auto size = 32768;
    for(i=start;i<start+size;i++)
    {
        fputc(Byte(i),fp);
    }
}
```



### 真实调用

在动态调试的过程中，调用JNI_OnLoad方法的地方不是init_array节内，而是libdvm.so文件中的dvmLoadNativeCode方法。

![](1561945707991.png)



### 分析不能停，探索JNI_OnLoad

#### 初遇小坑

图中圈起来的函数，最终跳到类似0x3FB8地址出的地方，为什么这个地方的函数地址是找不到的呢？

![](1561780143329.png)

![](1561780375025.png)



#### 蓦然回首，原来是重定位

由于这里调用的是第三方库函数，这里就用到了PLT表，每次调用第三方库函数都会跳到PLT条目中。这个表有关第三方函数的每一个条目都指向了GOT表条目的值，第一次访问第三方库函数的时候，实际上去执行了解析函数，将第三方库函数的内存地址存储到GOT表内并且调用，后面再次执库函数的时候，在PLT条目中就会直接执行到第三方库函数的内存地址处，而不用再次解析。

所以上面之所以找不到库函数地址，是因为重定位后被改写后的内存地址，在静态文件中是不能识别的。

绕过也是很简单的，因为我们解密的数据长度有限，我们将解密部分替换到原来的shella-3.0.0.0.so文件中即可，再次打开如下图所示，都是一些偏移可以被IDA识别出来

![](1561788195723.png)



#### 再现加密

第一次解密中的行为，这里i本身就是libshella-3.0.0.0.so文件的内存基址，这里将地址存进dword_4008变量中

![](1561867476953.png)

这里其实就是读取shella-3.0.0.0.so文件的名称到变量中

![ ](1561875873720.png)



接着将得到的libname和一个偏移值0x6D88（刚好指向libshella-3.0.0.0.so文件尾部附加数据开始的位置）作为参数传进函数内，执行以下操作

* 总共三次从尾部读取所有数据到内存，并进行解密运算
* 

![](1561949893405.png)



### 真JNI_OnLoad

这里调用了dlsym来在so文件中找到JNI_Onload符号地址并进行调用。

分析到这里其实除了之前的解密操作，我们并没有看到任何动态注册本地方法的地方，那么结合这里出现符号调用可以大胆猜想，这里可能会是二次解密后得到的JNI_OnLoad方法的源码位置，上面分析的应该只是一层加密的壳JNI_OnLoad方法，下面根据猜想进行小心求证

![](1561899531589.png)



动态调试跟进解密后的JNI_OnLoad方法

这里将壳入口类名作为参数传进函数，下面判断如果返回结果为0则打印出注册本地方法失败这样的字符串

![](1561972641741.png)



根据传入壳的入口类名作为参数进行类定位和注册本地方法

![](1561973384841.png)



### 惊现：0x35C

![](1562030739731.png)

发现偏移0x35C，这正是registerNatives相对于JNINativeInterface的偏移。他的第三个参数是`JNINativeMethod`结构体数组，第四个参数就是结构体数组的长度，注册方法数量。只要通过解析JNINativeMethod结构体即可得到注册本地方法的真实地址

```c
typedef struct {
    const char* name;
    const char* signature;
    void* fnPtr;
} JNINativeMethod;
```



#### 解析本地方法

注册方法数量为5。

本地方法对应内存地址

load	0x75700B1D

runCreate	0x756fc469

changeEnv	0x756FB37D

receiver	0x756f7621

txEntries	0x756FB0F9

```
0B 9E 70 75 10 9E 70 75  1D 0B 70 75 2D 9E 70 75
10 9E 70 75 69 C4 6F 75  37 9E 70 75 10 9E 70 75
7D B3 6F 75 41 9E 70 75  49 9E 70 75 21 76 6F 75
65 9E 70 75 6F 9E 70 75  F9 B0 6F 75 
```



### 骤现异常

要分析上面本地方法，就需要配合动态调试综合来进行。但是当我们在load方法上下断点后，程序并不能执行到这里，从日志中反馈一个`signal 11`的错误，并且程序也不能正常跑起来，弹出应用已经停止的窗口。

思考：我这里为了调试，第一：只是将AndroidManifest.xml文件添加了一个可调式属性。第二注释掉了几个public.xml中的几个无关属性防止反编译失败。第三就是签上了自定义签名。怎么会出现signal 11

![](1562233660124.png)



在网上找到一些类似的解决方法，先用addr2line命令定位出错的地方在库文件的什么地方，根据栈回溯backtrace打印出的内容来定位：`arm-none-linux-gnueabi-addr2line.exe 00022108 -e libc.so`，返回结果为`??:?`

这里我们卡在了脱壳的过程中，该解密的区段都已经解密成功了，就在即将要开始调用java层的native方法的时候，这里出现signal 11的错误，怎么办呢？



### 退一步海阔天空，注入大法好

虽然暂时无法确定出问题的细节，但是大致方向是可以把握的：**因为重打包后，程序出现崩溃**。

为什么要重打包？因为要要修改AndroidManifest.xml文件增加可调式属性，否则jdb无法启动应用。

那么有办法替代修改调试属性的操作吗？有，参考【9】，init注入或者xposed。这里直接用写好的工具[mprop](https://github.com/wpvsyou/mprop)，执行`./mprop ro.debuggable 1 `即可。



#### 绕过反调试，手动绕过isDebuggerConnected

当我们开始调试的时候，其实java层有一个反调试，就在壳代码中，最开始是通过反编译smali代码，删除相应代码来对抗它的，但是因为反编译后会出现程序异常，我们这里通过mprop绕过，接下来就需要绕过这里的反调试。

思路：

![](1562296193659.png)

【1】patch掉该处代码，重新修改dex文件头的signature和checksum

【2】动态修改isDebuggerConnected的返回值，参考【10】

这里我用的第二种方法



### load：核心逻辑

顺利到在load函数中下上断点。

![](1562314733720.png)



下面主要分析核心内容。

* 获取odex基址，0x750DD000

![](1562316617292.png)



* 获取dex文件偏移、地址，并且解密dex头部数据到内存中

![](1562333761188.png)



* 根据解密后的DEX头部0xE0字节数据+DEX偏移指向的剩余部分数据，结合起来就是原始DEX文件

dump解密后的头部0xe0字节数据

```c
static main(void)
{
    auto fp, begin, end, ptr;
    fp = fopen("d:\\header.dex", "wb");
    begin = 0x74fd7000;
    len = 0xe0;
    for ( ptr = begin; ptr < begin+len; ptr ++ )
        fputc(Byte(ptr), fp);
}
```

ida脚本打印ODEX文件在内存中的所有数据

```c
static main(void)
{
    auto fp, begin, end, ptr;
    fp = fopen("d:\\dump.odex", "wb");
    begin = 0x74fd7000;
    end = 0x75b2f000;
    for ( ptr = begin; ptr < end; ptr ++ )
        fputc(Byte(ptr), fp);
}
```



* dump出Dex header和整个ODEX文件数据后，然后根据Dex Header中的file_size字段dump出Dex文件，接着用正确的Dex Header头替换错误的头部即可(010edit：ctrl+shift+a，使用select Range即可)

![](1562394890758.png)



## 脱壳思路

1. 搜索DEX文件的magic字符`64 65 78 0a 30 33 35`，截取前0xE0长度的字符并dump到classes.dex本地文件中。获取偏移0x20处的文件大小长度。

2. 接着搜索/proc/<pid>/maps获取odex的内存基址，根据下面计算，得到dex文件偏移地址。a1+0x6C=data_off，a1+0x68=data_size

![ ](282719-20180328204952517-1717220309.png)

3. dex偏移 + ODex基址 + 0x28即Dex文件内存地址。结合文件大小dump出dex文件数据，接着去除前0xE0字节数据，将剩余内容写入classes.dex文件中



# 小结

【1】IDA在识别节头出错的情况下，会去识别程序头继续分析

【2】ELF基础：ELF节头表不能被装载进内存。由于ELF程序装载过程中只用到了程序头表

【3】#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l) >> 32) & 0xFFFFFFFF))

【4】`Alt+S`：修改段属性，将需要保存的段内存勾上loader选项，`TakeMemorySnapshot(1);`：IDC语句，直接打下内存快照

【5】0x28为odex文件格式中dex_header的相对偏移地址，所以(odexAddr + 0x28)为该odex文件格式中dex header的绝对地址

总的来说，是一次马马虎虎的脱壳路程，但是从结果看还是成功的。中途出现很多问题，耐心是必须的。不足也是很多的：

* JNI本地方法注册调用逻辑不熟悉，过程中的很多地方是参考其他文章学习到的。
* 伪代码也不是完全弄懂了，很多代码细节是模糊的





# 参考

【1】国内众多加固厂商存在有各自标志性的加固文件分析的时候可以快速识别

【2】[ELF的dump及修复思路](https://pkiller.com/android/ELF的dump及修复思路/)

【3】[section开源修复代码]( <https://github.com/WangYinuo/FixElfSection>)

【4】[乐固壳分析]( <https://www.cnblogs.com/goodhacker/p/8666217.html>)

【5】[[原创]乐固libshella 2.10.1分析笔记](<https://bbs.pediy.com/thread-218782.htm>)

【6】[Dalvik虚拟机JNI方法的注册过程分析](https://blog.csdn.net/Luoshengyang/article/details/8923483)

【7】[乐固2.8](https://my.oschina.net/jalen1991/blog/1870774)

【8】[Fatal signal 11问题的解决方法](https://blog.csdn.net/tankai19880619/article/details/9004619)

【9】[Android 「动态分析」打开调试开关的三种方法](https://blog.csdn.net/hp910315/article/details/82769506)

【10】[手动绕过百度加固Debug.isDebuggerConnected反调试的方法](https://blog.csdn.net/QQ1084283172/article/details/78237571)