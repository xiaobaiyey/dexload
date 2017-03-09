#pragma once
#include "dvmdata.h"
class Davlik
{
public:
	static Davlik* initdvm();
	bool loaddex(const char* DEXPath, jint & mcookie);
	void writeminidex(const char* minidex);
	bool initOk = false;




private:
	Davlik();
	~Davlik();
	char* clibdvmStr = "libdvm.so";
	int lookup(JNINativeMethod *table, const char *name, const char *sig, void(**fnPtrout)(uint32_t const *, union JValue *));
	
	void(*openDexFile)(const uint32_t* args, union  JValue* pResult);
	

};
