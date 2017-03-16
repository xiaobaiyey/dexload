#pragma once
#include "Davlikvm.h"
enum
{
	NEEDOPT=0,

};
class PluginDex
{
public:
	static  jboolean loadDex(JNIEnv* env, jobject obj, jstring dexpath);

private:
	PluginDex(JNIEnv* env,jstring dexpath);
	JNIEnv* env;
	jobject ClassLoader;
	char* DataFileDir;
	char* DataNativeDir;
	char* PackageName;
	char* DexFilePath;
	Davlik* davlik_;
	jobject getApplicationContext() const;
	jboolean startload();
	jboolean DexFileLoaddex(jmethodID loadDex, const char* cooketype);
	char* getoatdex(const char* path);

};
