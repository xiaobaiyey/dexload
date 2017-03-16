#include "pch.h"
#include "Artvm.h"
#include <dlfcn.h>
#include "Messageprint.h"
#include "Hook.h"
#include <asm-generic/fcntl.h>
#include "Security.h"
#include <cstdlib>
#include "dexload.h"
#include <sys/stat.h>
#include <sys/mman.h>
//--------------------------------------art open dex---------------------------------------------------
//for art
static int (*artoldopen)(const char* file, int oflag, ...);
static int (*artoldfstat)(int, struct stat*);
static ssize_t (*artoldread)(int fd, void* des, size_t request);

static void* (*artoldmmap)(void*, size_t, int, int, int, off_t);
static int (*artoldmprotect)(const void*, size_t, int);
static int (*artoldmunmap)(void*, size_t);
static ssize_t (*artold__read_chk)(int fd, void* buf, size_t count, size_t buf_size);
static int (*artoldfork)();
static int (*artoldexecv)(const char* name, char*const * argv);
//--------------------------------------------------------------------------------
//hook 是否标志
static bool stopArtHook = false;

static char fdlinkstr[128] = {0};
static char linkPath[256] = {0};
//for test
//for android 4.0-6.0 /data/data/PackageName/files/code/xxxx.dex
static char dexdatadirone [256] = {0};
//for android 6.0-7.1 /data/user/0/PackageName/files/code/xxxx.dex
static char dexdatadirtwo[256] = {0};
//for android 4.0-6.0 /data/data/PackageName/files/opdir/libx.so
static char oatDatadirOne[256] = {0};
//for android 6.0-7.1 /data/user/0/PackageName/files/opdir/libx.so
static char oatDatadirTwo[256] = {0};
//------------------------------------------
// when open dex or oat file record fd
//dex fd
static int dexFileFd = -1;
//oat fd
static int oatFileFd = -1;
//------------------------------------------s
static unsigned char* dexAddress = nullptr;
#define MINIDEXSIZE 292
//oat file size
static  int oatFileSize = 0;
//if first time to run application  hook fork and exev.
static bool DisableDex2oat = true;

hidden int Artvm::artmyfstat(int fd, struct stat* s)
{
	if (stopArtHook)
	{
		return artoldfstat(fd, s);
	}
	memset(fdlinkstr, 0, 128);
	memset(linkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(fdlinkstr, "/proc/%d/fd/%d", pid, fd);
	int res = artoldfstat(fd, s);
	if (readlink(fdlinkstr, linkPath, 256) >= 0)
	{
		//if fstat dex or oat file then ....
		if (strcmp(linkPath, dexdatadirone) == 0 || strcmp(linkPath, dexdatadirtwo) == 0)
		{
			//if  st_size<=0
			if (s->st_size <= 0)return res;
			//else -292 (mini.dex size)
			s->st_size = s->st_size - MINIDEXSIZE;
			//Messageprint::printdebug("art load dex", "set success");
			//check dex fd
			if (dexFileFd == -1)dexFileFd = fd;
		}
		if (strcmp(linkPath, oatDatadirOne) == 0 || strcmp(linkPath, oatDatadirTwo) == 0)
		{
			/*//if  st_size<=0
			if (s->st_size <= 0)return res;
			//else -292 (mini.dex size)
			s->st_size = s->st_size - MINIDEXSIZE;*/
			//Messageprint::printdebug("art load dex", "set oat success");
			//check oat fd
			oatFileSize = s->st_size;
			if (oatFileFd == -1)oatFileFd = fd;
		}
		//Messageprint::printinfo("art load dex", "fstat fd:%d  path:%s", fd, linkPath);
	}
	return res;
}

hidden int Artvm::artmyopen(const char* pathname, int flags, ...)
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
	//pathname may be null
	if (pathname != nullptr)
	{
		//while open dex
		if (strcmp(pathname, dexdatadirone) == 0 || strcmp(pathname, dexdatadirtwo) == 0)
		{
			dexFileFd = fd;
			//Messageprint::printdebug("art load dex", "open dex success:%s fd:%d",pathname,fd);
		}
		if (strcmp(pathname, oatDatadirOne) == 0 || strcmp(pathname, oatDatadirTwo) == 0)
		{
			oatFileFd = fd;
			//Messageprint::printdebug("art load dex", "open oat success");
		}
		//||
		//Messageprint::printinfo("art load dex", "open oat:%s fd:%d", pathname, fd);
	}
	return fd;
}

hidden ssize_t Artvm::artmyread(int fd, void* des, size_t request)
{
	if (stopArtHook || fd == -1)
	{
		return artoldread(fd, des, request);
	}

	memset(fdlinkstr, 0, 128);
	memset(linkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(fdlinkstr, "/proc/%d/fd/%d", pid, fd);
	if (readlink(fdlinkstr, linkPath, 256) >= 0)
	{
		//2017年3月12日22:53:03
		//for dex magcic
		if (request == 4 && (strcmp(linkPath, dexdatadirone) == 0 || strcmp(linkPath, dexdatadirtwo) == 0))
		{
			memcpy(des, kDexMagic, 4);
			//Messageprint::printinfo("art load dex", "read magcic success");
			return 4;
		}
		//Messageprint::printinfo("art load dex", "read fd:%d request:%d  path:%s", fd, request, linkPath);
		//Messageprint::printinfo("art load dex", "read fd:%d request:%d  path:%s", fd, request, linkPath);
	}

	ssize_t res = artoldread(fd, des, request);
	return res;
}

hidden void artRc4(unsigned char* dexbytes, unsigned int len)
{
	//here set your key 
	char* key_str = RC4KEY;
	unsigned char initkey[256];
	rc4_init(initkey, (unsigned char*)key_str, strlen(key_str));
	rc4_crypt(initkey, dexbytes, len);
}

hidden void* Artvm::artmymmap(void* start, size_t len, int prot, int flags, int fd, off_t offset)
{
	if (stopArtHook || fd == -1)
	{
		return artoldmmap(start, len, prot, flags, fd, offset);
	}
	memset(fdlinkstr, 0, 128);
	memset(linkPath, 0, 256);
	pid_t pid = getpid();
	sprintf(fdlinkstr, "/proc/%d/fd/%d", pid, fd);
	if (readlink(fdlinkstr, linkPath, 256) >= 0)
	{
		//
		if (strcmp(linkPath, dexdatadirone) == 0 || strcmp(linkPath, dexdatadirtwo) == 0)
		{
			unsigned char* result = (unsigned char*)artoldmmap(start, len + 292, prot, flags, fd, offset);
			int res = mprotect(result, 0x70 + 292, PROT_WRITE | PROT_READ);
		//	Messageprint::printinfo("art load dex", "mprotect result:%d", res);
			artRc4((unsigned char*)result + 292, 0x70);
			mprotect(result, 0x70 + 292, prot);
			//Messageprint::printinfo("art load dex", "mmap dex success");
			dexAddress = (result + 292);
			return result + 292;
		}
		if ((strcmp(linkPath, oatDatadirOne) == 0 || strcmp(linkPath, oatDatadirTwo) == 0)&&offset==0&&len>0x1000)
		{
			unsigned char* result = (unsigned char*)artoldmmap(start, len, prot, flags, fd, offset);
			//此处不太准确 纯属经验（oat文件偏移0x1000 处为oat文件头文件）后面在有时间解析
			int res = mprotect(result, len, PROT_WRITE | PROT_READ);
			//Messageprint::printinfo("art load dex", "mprotect result:%d", res);
			OatHeader* oat_header = (OatHeader*)(result + 0x1000);
			//Messageprint::printinfo("art load dex", "mmap oat  mageic:%s",oat_header->magic);
			int sizeofOatHeader = sizeof(OatHeader)+oat_header->keyValueStoreSize;
			//接下来即为OatDexFile 头
			OatDexFileBefore* before = (OatDexFileBefore*)(result + 0x1000 + sizeofOatHeader);
			//解析dex头文件所在位置before+4+dex_file_location_data_
			OatDexFileAfter* after = (OatDexFileAfter*)(result+0x1000+sizeofOatHeader+4+before->dex_file_location_size_);
			unsigned char* dexdata = result + 0x1000 + after->dex_file_offset_;//为dex文件头所在的偏移
			//解密 dex头
			artRc4(dexdata, 0x70);
			mprotect(result,len, prot);
			//返回 ok;
			//Messageprint::printinfo("art load dex", "mmap oat start:0x%08x port:%d len:0x%08x fd:%d offset:0x%x path:%s", start, prot, len, fd, offset, linkPath);
			return  result;
		}
		//Messageprint::printinfo("art load dex", "mmap oat start:0x%08x port:%d len:0x%08x fd:%d offset:0x%x path:%s", start, prot, len, fd, offset, linkPath);
	}
	return artoldmmap(start, len, prot, flags, fd, offset);
}


hidden int Artvm::artmymprotect(const void* des, size_t size, int fd)
{
	return 0;
}

hidden int Artvm::artmymunmap(void* des, size_t size)
{
	if (stopArtHook)
	{
		return artoldmunmap(des, size);
	}
	if (des == dexAddress)
	{
		//Messageprint::printinfo("art load dex", " artmymunmap set success");
		char* dest = (char*)des;
		dexAddress = nullptr;
		return artoldmunmap(dest - 292, size);
	}
	return artoldmunmap(des, size);
}


/*
* call before LoadDex method
* for  dexc is like xxxx.dex
* for oatc_text like lib.oat
*/
hidden void Artvm::setdexAndoat(const char* dexc, const char* oatc_text)
{
	memset(dexdatadirone, 0, 256);
	memset(dexdatadirtwo, 0, 256);
	memset(oatDatadirOne, 0, 256);
	memset(oatDatadirTwo, 0, 256);
	//set dex path
	sprintf(dexdatadirone, "/data/data/%s/files/code/%s", PackageNames, dexc);
	sprintf(dexdatadirtwo, "/data/user/0/%s/files/code/%s", PackageNames, dexc);
	//set oat path
	sprintf(oatDatadirOne, "/data/data/%s/files/optdir/%s", PackageNames, oatc_text);
	sprintf(oatDatadirTwo, "/data/user/0/%s/files/optdir/%s", PackageNames, oatc_text);
}

hidden void Artvm::setPluginDexAndOat(const char* dexfilePath, const char* oat,const char*packageName)
{
	memset(dexdatadirone, 0, 256);
	memset(dexdatadirtwo, 0, 256);
	memset(oatDatadirOne, 0, 256);
	memset(oatDatadirTwo, 0, 256);

	sprintf(dexdatadirone, "%s", dexfilePath);
	sprintf(dexdatadirtwo, "%s", dexfilePath);
	//set oat path
	sprintf(oatDatadirOne, "/data/data/%s/files/plugindir/%s", packageName, oat);
	sprintf(oatDatadirTwo, "/data/user/0/%s/files/plugindir/%s", packageName, oat);
}
hidden void Artvm::hookstart()
{
	if (haveHook)
	{
		return;
	}
	void* arthandle = dlopen("/system/lib/libc.so", 0);
	Hook::hookMethod(arthandle, "open", (void*)artmyopen, (void**)(&artoldopen));
	Hook::hookMethod(arthandle, "read", (void*)artmyread, (void**)(&artoldread));
	Hook::hookMethod(arthandle, "munmap", (void*)artmymunmap, (void**)(&artoldmunmap));
	Hook::hookMethod(arthandle, "mmap", (void*)artmymmap, (void**)(&artoldmmap));
	Hook::hookMethod(arthandle, "fstat", (void*)artmyfstat, (void**)(&artoldfstat));
	Hook::hookMethod(arthandle, "fork", (void*)artmyfork, (void**)(&artoldfork));
	Hook::hookMethod(arthandle, "execv", (void*)artmyexecv, (void**)(&artoldexecv));
#if defined(__arm__)
	Hook::hookAllRegistered();
#endif
	dlclose(arthandle);
	haveHook = true;
}

hidden void Artvm::hookEnable(bool isenable)
{
	stopArtHook = isenable;
}

hidden int Artvm::artmyfork()
{
	if (stopArtHook)
	{
		return artoldfork();
	}
	if (DisableDex2oat)
	{
		return -1;
	}
	Messageprint::printinfo("artpre", "fork start");
	return -1;
}

hidden int Artvm::artmyexecv(const char* name, char* const* argv)
{
	//
	if (stopArtHook)
	{
		return artoldexecv(name, argv);
	}
	if (DisableDex2oat)
	{
		return -1;
	}
	Messageprint::printinfo("artpre", "fork start");
	return -1;
}


hidden void* Artvm::startselfDex2oat(void* argsdata)
{
	sleep(5);
	//Messageprint::printinfo("arg load dex", "startselfDex2oat");
	ArmDex2oatArg* args = (struct ArmDex2oatArg*)argsdata;
	makedex2oat(args->DEXPATH, args->OATPATH, args->SDKINT, args->NATIVEPATH,args->PACKAGENAME,args->DEXNAME,args->OATNAME,args->TYPE);
	return nullptr;
}

/**
 * \brief 
 * \param DEX_PATH 
 * \param OAT_PATH 
 * \param sdk_int 
 * \param NativeLibDir 
 * \param dexName 
 * \param oatName 
 */
hidden void Artvm::needDex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir,const char* dexName,const char* oatName,int TYPE)
{
	//7.0 oat 优化暂时没处理好
	if (sdk_int>=24)
	{
		return;
	}
	//if file not exist hook fork and exev then make dex2oat by ourself
	if (access(OAT_PATH, F_OK) == -1)
	{
		DisableDex2oat = true;
		char* dex = strdup(dexName);
		char* oat = strdup(oatName);
		char* native = strdup(NativeLibDir);
		ArmDex2oatArg* args = new ArmDex2oatArg;
		//dex file path
		args->DEXPATH = strdup(DEX_PATH);
		//oat file path
		args->OATPATH = strdup(OAT_PATH);
		//dex 
		args->DEXNAME = dex;
		//oat
		args->OATNAME = oat;
		//oat 
		args->NATIVEPATH = native;
		//sdk
		args->SDKINT = sdk_int;
		//packagename
		args->PACKAGENAME = strdup(PackageNames);
		//plugin or load all
		args->TYPE = TYPE;
		pthread_t id;
		pthread_create(&id, nullptr, &startselfDex2oat, args);
	}
	else
	{
		DisableDex2oat = false;
	}
}



/**
 * \brief 
 * \param DEX_PATH  dex file name
 * \param OAT_PATH  oat file name
 * \param sdk_int  sdk version
 * \param NativeLibDir  native lib
 * \param packageName  packagename
 * \param dexName  dex name
 * \param oatName  oat name
 * \param TYPE  type
 * \return if dex2oat success
 */
hidden bool Artvm::makedex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir,const char* packageName, const char* dexName, const char* oatName,int TYPE)
{
	//if oat file exist retrun true
	if (access(OAT_PATH, F_OK) == -1)
	{
		std::string cmd;
		//DEX_PATH="/data/data/com.xiaobai.loaddextest/files/code/encrypt0.dex" 
		cmd.append("DEX_NAME=\"");
		cmd.append(dexName);
		cmd.append("\" ");
		//OAT_PATH="/data/local/tmp/test.so"   
		cmd.append("OAT_NAME=\"");
		cmd.append(oatName);
		cmd.append("\" ");

		////PACKAGENAMW="xxx"
		cmd.append("Packge=\"");
		cmd.append(packageName);
		cmd.append("\" ");

		////PACKAGENAMW="xxx"
		cmd.append("DEX_PATH=\"");
		cmd.append(DEX_PATH);
		cmd.append("\" ");

		char type[2] = { 0 };
		sprintf(type, "%d",TYPE);
		cmd.append("TYPE=\"");
		cmd.append(type);
		cmd.append("\" ");

		//LD_PRELOAD="/data/app/com.catchingnow.icebox-1/lib/arm/libdexload.so"
		cmd.append("LD_PRELOAD=\"");
		char* paths = new char[256];
		memset(paths, 0, 256);
		sprintf(paths, "%s/libdexload.so", NativeLibDir);
		cmd.append(paths);
		cmd.append("\" ");

		cmd.append("SDK_INI=\"");
		char sdk[2] = {0};
		sprintf(sdk, "%d", sdk_int);
		cmd.append(sdk);
		cmd.append("\" ");

		cmd.append("/system/bin/dex2oat ");
#if defined(__i386__)
		cmd.append("--instruction-set=x86 ");
#else
		cmd.append("--instruction-set=arm ");
#endif
		//--boot-image=/system/framework/boot.art 
		cmd.append("--boot-image=/system/framework/boot.art ");
		//--dex-file=/data/data/com.xiaobai.loaddextest/files/code/encrypt0.dex 
		cmd.append("--dex-file=");
		cmd.append(DEX_PATH);
		cmd.append(" ");

		//--oat-file=/data/local/tmp/test.so 
		cmd.append("--oat-file=");
		cmd.append(OAT_PATH);
		cmd.append(" ");

		cmd.append("--compiler-filter=interpret-only");

		//Messageprint::printinfo("dex2oat1111", "cmd:%s", cmd.c_str());
		//artprestophook = true;
		int optres = system(cmd.c_str());
		//artprestophook = false;
		Messageprint::printinfo("dex2oat1111111", "optres:%d", optres);
		if (access(OAT_PATH, F_OK) == -1)
		{
			Messageprint::printinfo("dex2oat", "opt fail");
			return false;
		}
		else
		{
			Messageprint::printinfo("dex2oat", "opt success");
			return true;
		}
	}
	else
	{
		return true;
	}
}

