#include "pch.h"
#include "Artvm.h"
#include <dlfcn.h>
#include "Messageprint.h"
#include "Hook.h"
#include <asm-generic/fcntl.h>
#include "Security.h"

//--------------------------------------art open dex---------------------------------------------------
//for art
static int (*artoldopen)(const char* file, int oflag, ...);
static int (*artoldfstat)(int, struct stat*);
static ssize_t (*artoldread)(int fd, void* des, size_t request);
static ssize_t (*artoldwrite)(int, const void*, size_t);
static void* (*artoldmmap)(void*, size_t, int, int, int, off_t);
static int (*artoldmprotect)(const void*, size_t, int);
static int (*artoldmunmap)(void*, size_t);
static bool stopArtHook;


static 	const char* dex="";
static const char* ota="";
static	int artdexfd=0;
static int artoatdexfd=0;


int Artvm::artmyfstat(int fd, stat* s)
{
	int res = artoldfstat(fd, s);
	if (stopArtHook)
	{
		return res;
	}

	Messageprint::printinfo("art load dex", "fstat fd:%d", fd);
	return res;
}

ssize_t Artvm::artmyread(int fd, void* des, size_t request)
{
	if (stopArtHook)
	{
		return artoldread(fd, des, request);
	}

	if (fd==-1||(artdexfd!=0&&artoatdexfd!=0))
	{
		return artoldread(fd, des, request);
	}
	else if(request==4&&fd==artdexfd)
	{
		memcpy(des, "dex\n", 4u);
		return 4;
	}
	ssize_t res = artoldread(fd, des, request);
	Messageprint::printinfo("art load dex", "read fd:%d request:%d read:%d", fd, request, res);
	return res;
}

ssize_t Artvm::artmywrite(int, const void*, size_t)
{
	return ssize_t();
}

hidden void artRc4(unsigned char*dexbytes, unsigned int len)
{
	//here set your key 
	char* key_str = "HF(*$EWYH*OFHSY&(F(&*Y#$(&*Y";
	unsigned char initkey[256];
	rc4_init(initkey, (unsigned char*)key_str, strlen(key_str));
	if (len <= 1000)
	{
		rc4_crypt(initkey, dexbytes, len);
	}
	else
	{
		rc4_crypt(initkey, dexbytes, 1000);
	}

}

void* Artvm::artmymmap(void* start, size_t len, int prot, int flags, int fd, off_t offset)
{
	if (stopArtHook)
	{
		return artoldmmap(start, len, prot, flags, fd, offset);
	}
	if (fd!=-1&&fd==artdexfd)
	{
		unsigned char* res = (unsigned char*)artoldmmap(start, len, prot, flags, fd, offset);
		artRc4(res, len);
		return  res;
	}

	Messageprint::printinfo("art load dex", "mmap dex start:0x%08x port:%d len:0x%08x fd:%d offset:0x%x", start, prot, len, fd, offset);
	return artoldmmap(start, len, prot, flags, fd, offset);
}

int Artvm::artmymprotect(const void* des, size_t size, int fd)
{
	return 0;
}

int Artvm::artmymunmap(void* des, size_t size)
{
	if (stopArtHook)
	{
		return artoldmunmap(des, size);
	}
	Messageprint::printinfo("art load dex", "munmap:0x%08x,size:%d", des, size);
	return artoldmunmap(des, size);
}

int Artvm::artmyopen(const char* pathname, int flags, ...)
{
	mode_t mode = 0;
	if ((flags & O_CREAT) != 0)
	{
		va_list args;
		va_start(args, flags);
		mode = static_cast<mode_t>(va_arg(args, int));
		va_end(args);
	}
	int fd = artoldopen(pathname, flags, mode);
	if (stopArtHook)
	{
		return fd;
	}
	if (strcmp(dex,pathname)==0)
	{
		artdexfd = fd;
	}
	else if(strstr(pathname,ota)!=nullptr)
	{
		artoatdexfd = fd;
	}
	Messageprint::printinfo("art load dex", "open oat:%s fd:%d", pathname, fd);
	return fd;
}


void Artvm::setdexAndoat(const char * dexc, const char * oatc_text)
{
	char* dexstr = strdup(dexc);
	dex = dexstr;
	char* oatstr = strdup(oatc_text);
	ota = oatstr;
	artdexfd = 0;
	artoatdexfd = 0;
}

void Artvm::hookstart()
{
	void* arthandle = dlopen("libart.so", 0);
	Hook::hookMethod(arthandle, "open", (void*)artmyopen, (void**)(&artoldopen));
	Hook::hookMethod(arthandle, "read", (void*)artmyread, (void**)(&artoldread));
	Hook::hookMethod(arthandle, "munmap", (void*)artmymunmap, (void**)(&artoldmunmap));
	Hook::hookMethod(arthandle, "mmap", (void*)artmymmap, (void**)(&artoldmmap));
	//Hook::hookMethod(arthandle, "mprotect", (void*)artmymprotect, (void**)(&artoldmprotect));
	//Hook::hookMethod(arthandle, "write", (void*)artmywrite, (void**)(&artoldwrite));
#if defined(__arm__)
	Hook::hookAllRegistered();
#endif
	dlclose(arthandle);
}

void Artvm::hookEnable(bool isenable)
{
	stopArtHook = isenable;
}
