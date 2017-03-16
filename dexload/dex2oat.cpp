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
#include <sys/stat.h>
#include <elf.h>
//大前提采用系统dex2oat 自定义oat 暂时没能力搞
static int (*dex2oatoldopen)(const char* file, int oflag, ...);

static int (*dex2oatoldfstat)(int, struct stat*);
static ssize_t (*dex2oatoldread)(int fd, void* des, size_t request);
static ssize_t (*dex2oatoldwrite)(int, const void*, size_t);
static void* (*dex2oatoldmmap)(void*, size_t, int, int, int, off_t);
static int (*dex2oatoldmprotect)(const void*, size_t, int);
static int (*dex2oatoldmunmap)(void*, size_t);
static ssize_t (*dex2oatoldpwrite)(int fd, const void* buf, size_t count, off_t offset);

static unsigned long SDK_INTART = 0;

//for test
//for android 4.0-6.0 /data/data/PackageName/files/code/xxxx.dex
static char dex2oatdexdirone[256] = {0};
//for android 6.0-7.1 /data/user/0/PackageName/files/code/xxxx.dex
static char dex2oatdexdirtwo[256] = {0};
//for android 4.0-6.0 /data/data/PackageName/files/opdir/libx.so
static char dex2oatoatdirOne[256] = {0};
//for android 6.0-7.1 /data/user/0/PackageName/files/opdir/libx.so
static char dex2oatoatdirTwo[256] = {0};
//dex 文件fd;
static int dexfd = -1;

//oat 文件fd 在OATwrite方法中用到
static int oatfd = -1;
//fd 
static char dex2oatfdlinkstr[128] = {0};
static char dex2oatlinkPath[256] = {0};


static int dex2oatdexSize = 0;

static unsigned char sbox[256] = {0};

static void* formprotectAddr = nullptr;

static bool stopdex2oatHook = false;
hidden void dex2oatRc4(unsigned char* dexbytes, unsigned int len)
{
	//here set your key 
	char* key_str = "1234567890";
	unsigned char initkey[256];
	rc4_init(initkey, (unsigned char*)key_str, strlen(key_str));
	rc4_crypt(initkey, dexbytes, len);
}


hidden void* dex2oatmmap(void* start, size_t len, int prot, int flags, int fd, off_t offset)
{
	if (fd == -1 || stopdex2oatHook)
	{
		return dex2oatoldmmap(start, len, prot, flags, fd, offset);
	}
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		if (strcmp(dex2oatlinkPath, dex2oatdexdirone) == 0 || strcmp(dex2oatlinkPath, dex2oatdexdirtwo) == 0)
		{
			unsigned char* result = (unsigned char*)dex2oatoldmmap(start, len + 292, prot, flags, fd, offset);
			int res = mprotect(result, 0x70 + 292, PROT_WRITE | PROT_READ);
			//Messageprint::printinfo("dex2oat1111", "mprotect result:%d", res);
			dex2oatRc4((unsigned char*)result + 292, 0x70);
			mprotect(result, 0x70 + 292, prot);
			//Messageprint::printinfo("dex2oat1111", "mmap dex success");
			formprotectAddr = result + 292;
			return result + 292;
		}
		if (strcmp(dex2oatlinkPath, dex2oatoatdirOne) == 0 || strcmp(dex2oatlinkPath, dex2oatoatdirTwo) == 0)
		{
			unsigned char* result = (unsigned char*)dex2oatoldmmap(start, len, prot, flags, fd, offset);

			//Messageprint::printinfo("dex2oat1111", "mmap oat start:0x%08x port:%d len:0x%08x fd:%d offset:0x%x path:%s", start, prot, len, fd, offset, dex2oatlinkPath);
		}
		//Messageprint::printinfo("dex2oat 1", "mmap start:0x%08x port:%d len:0x%08x fd:%d offset:0x%x path:%s", start, prot, len, fd, offset, dex2oatlinkPath);
	}
	void* result = dex2oatoldmmap(start, len, prot, flags, fd, offset);
	return result;
}


hidden static int dex2oatopen(const char* pathname, int flags, ...)
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
		//while open dex
		if (strcmp(pathname, dex2oatdexdirone) == 0 || strcmp(pathname, dex2oatdexdirtwo) == 0)
		{
			dexfd = fd;
			//Messageprint::printdebug("dex2oat1111", "open dex success");
		}
		if (strcmp(pathname, dex2oatoatdirOne) == 0 || strcmp(pathname, dex2oatoatdirTwo) == 0)
		{
			oatfd = fd;
			//Messageprint::printdebug("dex2oat1111", "open oat success");
		}
		//Messageprint::printinfo("dex2oat 1", "open oat:%s fd:%d", pathname, fd);
	}
	return fd;
}

hidden int dex2oatfstat(int fd, struct stat* st)
{
	//正常方法
	if (stopdex2oatHook || fd == -1)
	{
		return dex2oatoldfstat(fd, st);
	}
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	int res = dex2oatoldfstat(fd, st);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		//if fstat dex or oat file then ....
		if (strcmp(dex2oatlinkPath, dex2oatdexdirone) == 0 || strcmp(dex2oatlinkPath, dex2oatdexdirtwo) == 0)
		{
			//if  st_size<=0
			if (st->st_size <= 0)return res;
			//else -292 (mini.dex size)
			st->st_size = st->st_size - 292;
			//Messageprint::printdebug("dex2oat1111", "set dex success");
			//check dex fd
			dex2oatdexSize = st->st_size;
			if (dexfd == -1)dexfd = fd;
		}
		if (strcmp(dex2oatlinkPath, dex2oatoatdirOne) == 0 || strcmp(dex2oatlinkPath, dex2oatoatdirTwo) == 0)
		{
			/*//if  st_size<=0
			if (st->st_size <= 0)return res;
			//else -292 (mini.dex size)
			st->st_size = st->st_size - 292;*/
			Messageprint::printdebug("dex2oat1111", "set oat success");
			//check oat fd
			if (oatfd == -1)oatfd = fd;
		}
		//Messageprint::printinfo("dex2oat1111", "fstat fd:%d  path:%s", fd, dex2oatlinkPath);
	}
	return res;
}

hidden ssize_t dex2oatread(int fd, char* dest, size_t request)
{
	if (stopdex2oatHook || fd == -1)
	{
		return dex2oatoldread(fd, dest, request);
	}
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	ssize_t res = dex2oatoldread(fd, dest, request);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0 && dex2oatlinkPath != nullptr)
	{ //2017年3月12日22:53:03
		//for dex magcic
		if (request == 4 && (strcmp(dex2oatlinkPath, dex2oatdexdirone) == 0 || strcmp(dex2oatlinkPath, dex2oatdexdirtwo) == 0))
		{
			memcpy(dest, kDexMagic, 4);
			//Messageprint::printinfo("dex2oat1111", "read magcic success");
			return 4;
		}
		//Messageprint::printinfo("dex2oat 1", "read fd:%d request:%d  path:%s", fd, request, dex2oatlinkPath);
	}
	return res;
}



hidden ssize_t dex2oatwrite(int fd, const void* dec, size_t request)
{
	if (stopdex2oatHook)
	{
		return dex2oatoldwrite(fd, dec, request);
	}

	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		if ((strcmp(dex2oatlinkPath, dex2oatoatdirOne) == 0 || strcmp(dex2oatlinkPath, dex2oatoatdirTwo) == 0) && request == dex2oatdexSize)
		{
			unsigned char* data = new unsigned char[request];
			memset(data, 0, request);
			memcpy(data, dec, request);
			dex2oatRc4(data, 0x70);
			ssize_t res = dex2oatoldwrite(fd, data, request);
			delete[]data;
			//Messageprint::printinfo("dex2oat 1", "write file success");
			return res;
		}
		//Messageprint::printinfo("dex2oat 1", "write oatfile fd:%d  request:%d writeed:%s", fd, request, dex2oatlinkPath);
	}
	
	ssize_t res = dex2oatoldwrite(fd, dec, request);
	return res;
}

hidden int dex2oatmprotect(const void* des, size_t size, int s)
{
	if (des == formprotectAddr)
	{
		return dex2oatoldmprotect((char*)des - 292, size, s);
	}

	return dex2oatoldmprotect(des, size, s);
}
 
hidden int dex2oatmunmap(void* des, size_t size)
{
	//set mummap fail
	return 0;
}
//
static size_t(*dex2oatoldmsync)(void * addr, size_t len, int flags);
hidden size_t dex2oatmsync(void * addr, size_t len, int flags)
{
	//Messageprint::printinfo("dex2oat1 ", "sync 0x%08x %d %d",addr,len, flags);
	return dex2oatoldmsync(addr,len,flags);
}
static  ssize_t (*dex2oatoldpread64)(int fd, void* buf, size_t count, off_t offset);
hidden ssize_t dex2oatpread64(int fd, void* buf, size_t count, off_t offset)
{
	memset(dex2oatfdlinkstr, 0, 128);
	memset(dex2oatlinkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(dex2oatfdlinkstr, "/proc/%ld/fd/%d", pid, fd);
	if (readlink(dex2oatfdlinkstr, dex2oatlinkPath, 256) >= 0)
	{
		Messageprint::printinfo("dex2oat 1", "pread64 fd:%d  request:%d  offset:%d writeed:%s", fd, count,offset, dex2oatlinkPath);
	}
	return dex2oatoldpread64(fd, buf, count, offset);
}
hidden void getEnvText()
{
	char* dexc = getenv("DEX_NAME");
	//rc4Key = getenv("RC4KEY");
	char* INIT = getenv("SDK_INI");
	SDK_INTART = strtoul(INIT, nullptr, 0xa);
	char* oatc_text = getenv("OAT_NAME");
	char* PackageNames = getenv("Packge");
	memset(dex2oatdexdirone, 0, 256);
	memset(dex2oatdexdirtwo, 0, 256);
	memset(dex2oatoatdirOne, 0, 256);
	memset(dex2oatoatdirTwo, 0, 256);
	char* cType = getenv("TYPE");
	int TYPE = strtoul(cType,nullptr, 0xa);
	if (TYPE==0)
	{
		//set dex path
		sprintf(dex2oatdexdirone, "/data/data/%s/files/code/%s", PackageNames, dexc);
		sprintf(dex2oatdexdirtwo, "/data/user/0/%s/files/code/%s", PackageNames, dexc);
		//set oat path
		sprintf(dex2oatoatdirOne, "/data/data/%s/files/optdir/%s", PackageNames, oatc_text);
		sprintf(dex2oatoatdirTwo, "/data/user/0/%s/files/optdir/%s", PackageNames, oatc_text);
	}
	else
	{
		char* dex_path = getenv("DEX_PATH");
		sprintf(dex2oatdexdirone, "%s", dex_path);
		sprintf(dex2oatdexdirtwo, "%s", dex_path);
		sprintf(dex2oatoatdirOne, "/data/data/%s/files/optdir/%s", PackageNames, oatc_text);
		sprintf(dex2oatoatdirTwo, "/data/user/0/%s/files/optdir/%s", PackageNames, oatc_text);
	}



	/*Messageprint::printinfo("dex2oat1111", "dex path:%s", dex2oatdexdirone);
	Messageprint::printinfo("dex2oat1111", "dex path:%s", dex2oatdexdirtwo);
	Messageprint::printinfo("dex2oat1111", "oat path:%s", dex2oatoatdirOne);
	Messageprint::printinfo("dex2oat1111", "oat path:%s", dex2oatoatdirTwo);*/
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
	Hook::hookMethod(arthandle, "munmap", (void*)dex2oatmunmap, (void**)(&dex2oatoldmunmap));
	Hook::hookMethod(arthandle, "mprotect", (void*)dex2oatmprotect, (void**)(&dex2oatoldmprotect));
	Hook::hookMethod(arthandle, "write", (void*)dex2oatwrite, (void**)(&dex2oatoldwrite));
#if defined(__arm__)
		Hook::hookAllRegistered();
#endif
	dlclose(arthandle);

	return oldInitLogging(argv);
}
