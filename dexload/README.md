### 前提
首先思路参考了MultiDex，代码参考了某某加固。
### 总览
![](http://images2015.cnblogs.com/blog/836057/201703/836057-20170316093418432-1173085699.png)
### Davlikvm
Davlik 内存加载技术比较成熟，网上资料也比较多
采用非常简答的方法：
实现下面这个系统方法：具体代码就不贴出来了
```cpp
Dalvik_dalvik_system_DexFile_openDexFile_bytearray(const u4* args,JValue* pResult)
```
在这个过程中需要注意下面的问题：
注意事项：
* 拿到gDvm.userDexFiles这个指针
解决方法：

```cpp
void dvmInternalNativeShutdown()
{
    dvmHashTableFree(gDvm.userDexFiles);
}
```
Hook dvmHashTableFree方法然后调用dvmInternalNativeShutdown方法，通过dvmHashTableFree参数拿到指针（方法来自看雪论坛）

通过这种方法可以实现简单的内存加载和对dex加密
### Art
art 内存加载技术网上资料不多,也没实现完整的。思路参考某某加固的代码。这样兼容性可能好一点。
首先是通过反射调用DexFiel.loadDex

```java
static public DexFile loadDex(String sourcePathName, String outputPathName,
        int flags) throws IOException
```
在调用loadDex之前hook下面这些方法

```cpp
Hook::hookMethod(arthandle, "open", (void*)artmyopen, (void**)(&artoldopen));
    Hook::hookMethod(arthandle, "read", (void*)artmyread, (void**)(&artoldread));
    Hook::hookMethod(arthandle, "munmap", (void*)artmymunmap, (void**)(&artoldmunmap));
    Hook::hookMethod(arthandle, "mmap", (void*)artmymmap, (void**)(&artoldmmap));
    Hook::hookMethod(arthandle, "fstat", (void*)artmyfstat, (void**)(&artoldfstat));
    Hook::hookMethod(arthandle, "fork", (void*)artmyfork, (void**)(&artoldfork));
    Hook::hookMethod(arthandle, "execv", (void*)artmyexecv, (void**)(&artoldexecv));
```
在文件读取过程中做一些小动作，就可以实现dex文件简单的加密。这样也可以实现dex"不落地加载"。可能这种方法不太完美，但是相对来说可能稳定一点。兼容性也相对好一点。

### 使用方法：

### 小结：
上面描述比较简单。整个过程还是比较复杂的，并且涉及到art dex2oat，工作量也是蛮大的。测试了4.4 、6.0、7.1 系统，其他机型没测试
熟悉了dex加载的整个过程。非常感谢某某加固
代码稍后整理将会开源，