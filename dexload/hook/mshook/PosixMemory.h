/*
 * PosixMemory.h
 *
 *  Created on: 2016Äê2ÔÂ22ÈÕ
 *      Author: peng
 */
#if defined(__i386__) || defined(__x86_64__)
#ifndef POSIXMEMORY_H_
#define POSIXMEMORY_H_

#include "CydiaSubstrate.h"
#include "SubstrateStruct.h"


extern "C" SubstrateMemoryRef SubstrateMemoryCreate(SubstrateAllocatorRef allocator, SubstrateProcessRef process, void *data, size_t size);
extern "C" void SubstrateMemoryRelease(SubstrateMemoryRef memory);
extern "C" void __clear_cache(void *beg, void *end);

struct SubstrateHookMemory {
	SubstrateMemoryRef handle_;

	SubstrateHookMemory(SubstrateProcessRef process, void *data, size_t size) :	handle_(SubstrateMemoryCreate(NULL, NULL, data, size)) {}

	~SubstrateHookMemory() {
		if (handle_ != NULL)
			SubstrateMemoryRelease(handle_);
	}
};

#endif /* POSIXMEMORY_H_ */
#endif