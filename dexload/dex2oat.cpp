#include "pch.h"
#include "pch.h"
#include "dex2ota.h"
#include "Messageprint.h"
#include <dlfcn.h>
#include "Hook.h"
#include <fcntl.h>
#include <cstdlib>
#include "Security.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
//大前提采用系统dex2oat 自定义oat 暂时没能力搞
/*
 *由于7.0问题 暂时弃用dex2oat 采用 dex快速加载
 *
 */
static int (*dex2oatoldopen)(const char* file, int oflag, ...);

static int (*dex2oatoldfstat)(int, struct stat*);
static ssize_t (*dex2oatoldread)(int fd, void* des, size_t request);
static ssize_t (*dex2oatoldwrite)(int, const void*, size_t);
static void* (*dex2oatoldmmap)(void*, size_t, int, int, int, off_t);
static int (*dex2oatoldmprotect)(const void*, size_t, int);
static int (*dex2oatoldmunmap)(void*, size_t);


static unsigned long SDK_INTART = 0;
//传入dex文件路径
static char* dexFilePath;
//传入oat文件路径
static char* oatFilePath;

//dex 文件fd;
static int dexfd = 0;

//oat 文件fd 在OATwrite方法中用到
static int oatfd = 0;
//初始化的s盒
//
static char dex2oatfdlinkstr[128] = { 0 };
static char dex2oatlinkPath[256] = { 0 };

static int totalsize = 1000;

static unsigned char sbox[256] = {0};

static bool stopdex2oatHook = false;
hidden void dex2oatRc4(unsigned char* dexbytes, unsigned int len)
{
	//here set your key 
	char* key_str = "1234567890";
	unsigned char initkey[256];
	rc4_init(initkey, (unsigned char*)key_str, strlen(key_str));
	memcpy(sbox, initkey, 256);
	if (len <= 1000)
	{
		rc4_crypt(initkey, dexbytes, len);
	}
	else
	{
		rc4_crypt(initkey, dexbytes, 1000);
	}
}

int dex2oatfstat(int fd, struct stat* st)
{
	//正常方法
	if (stopdex2oatHook)
	{
		return  dex2oatoldfstat(fd,st);
	}

	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		Messageprint::printinfo("dex2oat 1", "fstat  fd:%d   path:%s", fd, dex2oatlinkPath);
	}
	return dex2oatoldfstat(fd, st);
}

ssize_t dex2oatwrite(int fd, const void* dec, size_t request)
{
	if (stopdex2oatHook)
	{
		return  dex2oatoldwrite(fd, dec, request);
	}
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		Messageprint::printinfo("dex2oat 1", "write oatfile fd:%d  request:%d writeed:%s", fd, request, dex2oatlinkPath);
	}
	ssize_t res = dex2oatoldwrite(fd, dec, request);

	
	return res;
}

int dex2oatmprotect(const void* des, size_t size, int s)
{
	return dex2oatoldmprotect(des, size, s);
}

int dex2oatmunmap(void* des, size_t size)
{
	//set mummap fail
	return 0;
}

void dex2oatreadFileLink()
{
	char* dirPath = new char[64];
	memset(dirPath, 0, 128);
	pid_t dex2oatpid = getpid();
	sprintf(dirPath, "/proc/%d/fd", dex2oatpid);
	delete[]dirPath;
}


void* dex2oatmmap(void* start, size_t len, int prot, int flags, int fd, off_t offset)
{
	if (fd==-1||stopdex2oatHook)
	{
		return dex2oatoldmmap(start, len, prot, flags, fd, offset);
	}
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		Messageprint::printinfo("dex2oat 1", "mmap start:0x%08x port:%d len:0x%08x fd:%d offset:0x%x path:%s", start, prot, len, fd, offset, dex2oatlinkPath);
	}

	void* result = dex2oatoldmmap(start, len, prot, flags, fd, offset);
	return result;
}


ssize_t dex2oatread(int fd, char* dest, size_t request)
{
	if (stopdex2oatHook || fd == -1)
	{
		return dex2oatread(fd, dest, request);
	}
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	ssize_t res = dex2oatread(fd, dest, request);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0 && dex2oatlinkPath != nullptr)
	{
		Messageprint::printinfo("dex2oat 1", "read fd:%d request:%d  path:%s", fd, request, dex2oatlinkPath);
	}
	return res;
}

static int dex2oatopen(const char* pathname, int flags, ...)
{
	mode_t mode = 0;
	if ((flags & O_CREAT) != 0)
	{
		va_list args;
		va_start(args, flags);
		mode = static_cast<mode_t>(va_arg(args, int));
		va_end(args);
	}
	int fd = dex2oatoldopen(pathname, flags, mode);
	if (pathname != nullptr)
	{
		Messageprint::printinfo("dex2oat 1", "open oat:%s fd:%d", pathname, fd);
	}
	return fd;
	
}


void getEnvText()
{
	dexFilePath = getenv("DEX_PATH");
	//rc4Key = getenv("RC4KEY");
	char* INIT = getenv("SDK_INI");
	SDK_INTART = strtoul(INIT, nullptr, 0xa);
	oatFilePath = getenv("OAT_PATH");
	Messageprint::printinfo("loaddex", "dexpath:%s", dexFilePath);
}

/*留作测试 hook 函数太多 */
void art::InitLogging(char* argv[])
{
	if (stophook)
	{
		oldInitLogging(argv);
	}

	void* arthandle = dlopen("libart.so", 0);

	oldInitLogging = (void(*)(char**))dlsym(arthandle, "_ZN3art11InitLoggingEPPc");
	getEnvText();

	Hook::hookMethod(arthandle, "open", (void*)dex2oatopen, (void**)(&dex2oatoldopen));

	Hook::hookMethod(arthandle, "read", (void*)dex2oatread, (void**)(&dex2oatoldread));

	Hook::hookMethod(arthandle, "fstat", (void*)dex2oatfstat, (void**)(&dex2oatoldfstat));

	Hook::hookMethod(arthandle, "mmap", (void*)dex2oatmmap, (void**)(&dex2oatoldmmap));

	//Hook::hookMethod(arthandle, "mprotect", (void*)dex2oatmprotect, (void**)(&dex2oatoldmprotect));
	Hook::hookMethod(arthandle, "write", (void*)dex2oatwrite, (void**)(&dex2oatoldwrite));

#if defined(__arm__)
		Hook::hookAllRegistered();
#endif
	dlclose(arthandle);

	return oldInitLogging(argv);
}
