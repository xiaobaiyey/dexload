#pragma once
struct ArmDex2oatArg
{
	char* DEXPATH;
	char* OATPATH;
	char* NATIVEPATH;
	int SDKINT;
};
class Artvm
{
private:
	static int artmyfstat(int, struct stat*);
	static ssize_t artmyread(int fd, void* des, size_t request);
	static void* artmymmap(void*, size_t, int, int, int, off_t);
	static int artmymprotect(const void*, size_t, int);
	static int artmymunmap(void*, size_t);
	static int artmyopen(const char* pathname, int flags, ...);
	static int artmyfork();
	static int artmyexecv(const char* name, char*const * argv);
	static bool makedex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir);
	static void* startselfDex2oat(void* args);
public:
	static void setdexAndoat(const char* dex, const char* oat);
	static void hookstart();
	static void hookEnable(bool isenable);
	static void needDex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir);
	//

};
