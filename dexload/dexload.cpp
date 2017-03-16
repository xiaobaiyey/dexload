#include "dexload.h"
#include <assert.h>
#include <sys/system_properties.h>
#include "util.h"
#include "Messageprint.h"
#include <string>
#include <cstdlib>
#include "loaddata.h"
#include "PluginDex.h"
jint sdk_int;
bool isArt;
//set key before call loaddata::attachContextBaseContext
hidden char*RC4KEY;
static JNINativeMethod methods[] = {
	{ "attachBaseContext", "(Landroid/content/Context;)V", (void*)loaddata::attachContextBaseContext },
	{ "loadPluginDex", "(Ljava/lang/String;)Z", (void*)PluginDex::loadDex }
};


int jniRegisterNativeMethods(JNIEnv* env,
	const char* className,
	const JNINativeMethod* gMethods,
	int numMethods)
{
	jclass clazz;
	int tmp;
	clazz = env->FindClass(className);
	if (clazz == NULL) {

		return -1;
	}
	if ((tmp = env->RegisterNatives(clazz, gMethods, numMethods)) < 0) {
		return -1;
	}
	return 0;
}
static  int registerNativeMethods(JNIEnv *env) {
	return jniRegisterNativeMethods(env, "com/xiaobai/tools/Native", methods, sizeof(methods) / sizeof(methods[0]));
}
static void init(JNIEnv* env)
{
	jclass jclazz = env->FindClass("android/os/Build$VERSION");
	jfieldID SDK_INT = env->GetStaticFieldID(jclazz, "SDK_INT", "I");
	sdk_int = env->GetStaticIntField(jclazz, SDK_INT);
	if (sdk_int > 13)
	{
		jclass System = env->FindClass("java/lang/System");
		jmethodID System_getProperty = env->GetStaticMethodID(System,"getProperty","(Ljava/lang/String;)Ljava/lang/String;");

		jstring vm_version_name = env->NewStringUTF("java.vm.version");
		jstring vm_version_value = static_cast<jstring>(env->CallStaticObjectMethod(System, System_getProperty, vm_version_name));
		char* cvm_version_value = Util::jstringTostring(env, vm_version_value);
		env->DeleteLocalRef(vm_version_name);
		env->DeleteLocalRef(vm_version_value);
		double version = atof(cvm_version_value);
		free(cvm_version_value);
		if (version>=2)
		{
			isArt = true;
		}
		else
		{
			isArt = false;
		}
	}
	else
	{
		Messageprint::printerror(__FUNCTION__, "not support");
		exit(0);
	}
	///set rc4 key here !!!!!!
	RC4KEY = "1234567890";
	registerNativeMethods(env);
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv* env = NULL;
	if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK)
	{
		//LOGI("jni read fail");
		return -1;
	}
	init(env);
	//testJnihelptools();
	return JNI_VERSION_1_6;
}
