#ifndef DALVIK_COMMON_H_
#define DALVIK_COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>

typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;
typedef uint64_t u8;
typedef int8_t s1;
typedef int16_t s2;
typedef int32_t s4;
typedef int64_t s8;

struct RawDexFile
{
	char* cacheFileName;
	void* pDvmDex;//DvmDex
};

struct DexOrJar
{
	char* fileName;
	bool isDex;
	bool okayToFree;
	RawDexFile* pRawDexFile;
	void* pJarFile;//JarFile
	u1* pDexMemory; // malloc()ed memory, if any
};

typedef void (*HashFreeFunc)(void* ptr);

struct HashTable
{
	int tableSize; /* must be power of 2 */
	int numEntries; /* current #of "live" entries */
	int numDeadEntries; /* current #of tombstone entries */
	void* pEntries; /* array on heap */
	HashFreeFunc freeFunc;
	pthread_mutex_t lock;
};

typedef int(*HashCompareFunc)(const void* tableItem, const void* looseItem);
#endif  // DALVIK_COMMON_H_
