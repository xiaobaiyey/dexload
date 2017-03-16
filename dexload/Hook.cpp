#include "pch.h"
#include "Hook.h"
#include <dlfcn.h>
#include "Messageprint.h"

#if defined(__i386__) || defined(__x86_64__)
#include "hook/mshook/MSHook.h"
#else
#include "hook/arm/native_hook.h"
#endif

hidden Hook::Hook()
{
}


hidden Hook::~Hook()
{
}

hidden void Hook::hookMethod(void* handle, const char* symbol, void* new_func, void** old_func)
{
	void* addr = dlsym(handle, symbol);
	if (addr == nullptr)
	{
		Messageprint::printerror("tag","Error: unable to find the Symbol : %s.", symbol);
		return;
	}
#if defined(__i386__) || defined(__x86_64__)
	inlineHookDirect((unsigned int)(addr), new_func, old_func);
#else 
	int res= GodinHook::NativeHook::registeredHook((size_t)addr, (size_t)new_func, (size_t **)old_func);
	//Messageprint::printinfo("hookMethod", "result:%d", res);
#endif
}

hidden void Hook::hookMethod(void* handle, const std::string symbol, void* new_func, void** old_func)
{
	void* addr = dlsym(handle, symbol.c_str());
	if (addr == nullptr)
	{
		
		Messageprint::printerror("tag","Error: unable to find the Symbol : %s.", symbol.c_str());
		return;
	}
#if defined(__i386__) || defined(__x86_64__)
	inlineHookDirect((unsigned int)(addr), new_func, old_func);
#else
	GodinHook::NativeHook::registeredHook((size_t)addr, (size_t)new_func, (size_t **)old_func);
#endif
}

hidden void Hook::hookMethod(unsigned int addr, void* new_func, void** old_func)
{
#if defined(__i386__) || defined(__x86_64__)
	inlineHookDirect((unsigned int)(addr), new_func, old_func);
#else
	GodinHook::NativeHook::registeredHook((size_t)addr, (size_t)new_func, (size_t **)old_func);
#endif
}
#if defined(__arm__)
hidden void Hook::hookAllRegistered()
{
	GodinHook::NativeHook::hookAllRegistered();
}
#endif

