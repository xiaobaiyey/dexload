#pragma once
#include <string>

class Hook
{
public:
	Hook();
	~Hook();
	static void hookMethod(void* handle, const char* symbol, void* new_func, void** old_func);
	static void hookMethod(void* handle, const std::string symbol, void* new_func, void** old_func);
	static void hookMethod(unsigned int addr, void* new_func, void** old_func);
#if defined(__arm__)
	static void hookAllRegistered();
#endif
};
