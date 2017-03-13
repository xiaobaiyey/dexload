#include "pch.h"
#include "Davlikvm.h"
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "Messageprint.h"
#include <sys/mman.h>
#include <cstdio>
#include "Hook.h"
#include "Security.h"
//for dvm  292
hidden unsigned char MINIDEX[292] = {
	0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00, 0xD9, 0x24, 0x14, 0xFD, 0x2F, 0x81, 0x4D, 0x8B,
	0x50, 0x48, 0x13, 0x1D, 0x8D, 0xA9, 0xCF, 0x1F, 0xF1, 0xF2, 0xDD, 0x06, 0xB4, 0x67, 0x70, 0xA1,
	0x24, 0x01, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xD8, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x7C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x00,
	0xA4, 0x00, 0x00, 0x00, 0xB4, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0E, 0x4C, 0x63, 0x6F, 0x6D, 0x2F, 0x6D, 0x69, 0x78, 0x43, 0x6C, 0x61,
	0x73, 0x73, 0x3B, 0x00, 0x12, 0x4C, 0x6A, 0x61, 0x76, 0x61, 0x2F, 0x6C, 0x61, 0x6E, 0x67, 0x2F,
	0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x3B, 0x00, 0x0D, 0x6D, 0x69, 0x78, 0x43, 0x6C, 0x61, 0x73,
	0x73, 0x2E, 0x6A, 0x61, 0x76, 0x61, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x70, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x7C, 0x00, 0x00, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x02, 0x20, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0xD8, 0x00, 0x00, 0x00
};


//#if ENDIANNESS == "l"
#define HAVE_LITTLE_ENDIAN
//#else
//#define HAVE_BIG_ENDIAN
//#endif


void Davlik::writeminidex(const char* minidex)
{
	if (access(minidex,F_OK) == -1)
	{
		FILE* file = fopen(minidex, "wb");
		fwrite(MINIDEX, 292, 1, file);
		fclose(file);
	}
}

static int (*dvmRawDexFileOpenArray)(u1* pBytes, u4 length, RawDexFile** ppRawDexFile);
static void (*dvmInternalNativeShutdown)();
static void (*olddvmHashTableFree)(HashTable* pHashTable);
static bool dvmstophook = true;
static HashTable* gDvm_userDexFiles = nullptr;
static  void* (*dvmHashTableLookup)(HashTable* pHashTable, u4 itemHash, void* item, HashCompareFunc cmpFunc, bool doAdd);
static void mydvmHashTableFree(HashTable* pHashTable)
{
	if (dvmstophook)
	{
		return olddvmHashTableFree(pHashTable);
	}
	else
	{
		gDvm_userDexFiles = pHashTable;
		Messageprint::printerror("dvm", "Pointer get  gDvm_userDexFiles");
		return;
	}

}
hidden
Davlik::Davlik()
{
	void* libdvm = dlopen(clibdvmStr, 0);
	//_Z18dvmHashTableLookupP9HashTablejPvPFiPKvS3_Eb
	dvmHashTableLookup = (void*(*)(HashTable* pHashTable, u4 itemHash, void* item, HashCompareFunc cmpFunc, bool doAdd))dlsym(libdvm, "_Z18dvmHashTableLookupP9HashTablejPvPFiPKvS3_Eb");
	if (dvmHashTableLookup == nullptr)
	{
		initOk = false;
		Messageprint::printerror("dvm", "Pointer dvmHashTableLookup is null");
	}
	dvmRawDexFileOpenArray = (int(*)(u1* pBytes, u4 length, RawDexFile** ppRawDexFile)) dlsym(libdvm, "_Z22dvmRawDexFileOpenArrayPhjPP10RawDexFile");
	if (dvmRawDexFileOpenArray == nullptr)
	{
		initOk = false;
		Messageprint::printerror("dvm", "Pointer dvmRawDexFileOpenArray is null");
	}
	dvmInternalNativeShutdown = (void(*)()) dlsym(libdvm, "_Z25dvmInternalNativeShutdownv");
	if (dvmRawDexFileOpenArray == nullptr)
	{
		initOk = false;
		Messageprint::printerror("dvm", "Pointer dvmInternalNativeShutdown is null");
	}
	Hook::hookMethod(libdvm, "_Z16dvmHashTableFreeP9HashTable", (void*)mydvmHashTableFree, (void**)&olddvmHashTableFree);
#if defined(__arm__)
	Hook::hookAllRegistered();
#endif
	initOk = true;
}


Davlik::~Davlik()
{
}

Davlik* Davlik::initdvm()
{
	Davlik* davlik = new Davlik();

	return davlik;
}

// -----------------------dvm----------------
inline void dvmUnlockMutex(pthread_mutex_t* pMutex)
{
	int cc __attribute__((__unused__)) = pthread_mutex_unlock(pMutex);
	assert(cc == 0);
}


inline
void dvmLockMutex(pthread_mutex_t* pMutex)
{
	int cc __attribute__((__unused__)) = pthread_mutex_lock(pMutex);
	assert(cc == 0);
}

hidden void dvmHashTableLock(HashTable* pHashTable)
{
	dvmLockMutex(&pHashTable->lock);
}

hidden int hashcmpDexOrJar(const void* tableVal, const void* newVal)
{
	return (int)newVal - (int)tableVal;
}

inline void dvmHashTableUnlock(HashTable* pHashTable)
{
	dvmUnlockMutex(&pHashTable->lock);
}



/*
 * from dvm
 */
hidden void addToDexFileTable(DexOrJar* pDexOrJar)
{
	/*
	* Later on, we will receive this pointer as an argument and need
	* to find it in the hash table without knowing if it's valid or
	* not, which means we can't compute a hash value from anything
	* inside DexOrJar. We don't share DexOrJar structs when the same
	* file is opened multiple times, so we can just use the low 32
	* bits of the pointer as the hash.
	*/
	u4 hash = (u4)pDexOrJar;
	void* result;
	//get gDvm_userDexFiles
	dvmstophook = false;
	dvmInternalNativeShutdown();
	dvmstophook = true;
	if (gDvm_userDexFiles == nullptr)
	{
		Messageprint::printerror("dvm", "gDvm_userDexFiles is null");
		return;
	}

	dvmHashTableLock(gDvm_userDexFiles);
	result =dvmHashTableLookup(gDvm_userDexFiles, hash, pDexOrJar,
	                                    hashcmpDexOrJar, true);
	dvmHashTableUnlock(gDvm_userDexFiles);

	if (result != pDexOrJar)
	{
		Messageprint::printerror("dvm", "Pointer has already been added?");
		//dvmAbort();
	}

	pDexOrJar->okayToFree = true;
}

/*
 *dvm
* just for test 
*
*/
hidden void testRc4(u1*dexbytes, unsigned int len)
{
	//here set your key 
	char* key_str = "1234567890";
	unsigned char initkey[256];
	rc4_init(initkey, (unsigned char*)key_str, strlen(key_str));
	if (len<=1000)
	{
		rc4_crypt(initkey, dexbytes, len);
	}
	else
	{
		rc4_crypt(initkey, dexbytes, 0x70);
	}
	
}
/*
 * rewrite method
 */
hidden bool Davlik::loaddex(const char* DEXPath, jint& mcookie)
{
	RawDexFile* pRawDexFile;
	DexOrJar* pDexOrJar = NULL;
	FILE* file = fopen(DEXPath, "rb");
	fseek(file, 0, SEEK_END);
	u4 length = ftell(file);
	rewind(file);
	if (length <= 0)
	{
		Messageprint::printerror("dvm", "dex file len is zore");
		return false;
	}

	u1* pBytes = (u1*)malloc(length);
	if (pBytes == NULL)
	{
		Messageprint::printerror("dvm", "unable to allocate DEX memory");
		return false;
	}
	fread(pBytes, 1, length, file);
	fclose(file);
	testRc4(pBytes, length);
	if (dvmRawDexFileOpenArray(pBytes, length, &pRawDexFile) != 0)
	{
		Messageprint::printerror("dvm", "Unable to open in-memory DEX file");
		free(pBytes);
		return false;
	}
	pDexOrJar = (DexOrJar*)malloc(sizeof(DexOrJar));
	pDexOrJar->isDex = true;
	pDexOrJar->pRawDexFile = pRawDexFile;
	pDexOrJar->pDexMemory = pBytes;
	pDexOrJar->fileName = strdup("<memory>"); // Needs to be free()able.
	addToDexFileTable(pDexOrJar);
	mcookie =(jint)pDexOrJar;
	return true;
}
