#include "dexload.h"
#include <assert.h>
#include <sys/system_properties.h>
#include "util.h"
#include "Messageprint.h"
#include <string>
#include <cstdlib>
#include "loaddata.h"
jint sdk_int;
bool isArt;

static JNINativeMethod methods[] = {
	{ "run", "(Landroid/content/Context;)V", (void*)loaddata::attachContextBaseContext },
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
int registerNativeMethods(JNIEnv *env) {
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
		jclass SystemProperties = env->FindClass("android/os/SystemProperties");
		jmethodID SystemProperties_get = env->GetStaticMethodID(SystemProperties, "get", "(Ljava/lang/String;)Ljava/lang/String;");
		jstring vmname = env->NewStringUTF("java.vm.name");
		jstring vmvalue = static_cast<jstring>(env->CallStaticObjectMethod(System, System_getProperty, vmname));
		char* cvmvalue = Util::jstringTostring(env, vmvalue);
		env->DeleteLocalRef(vmname);
		env->DeleteLocalRef(vmvalue);
		Messageprint::printinfo("tag", "java.vm.name:%s", cvmvalue);
		jstring vm_version_name = env->NewStringUTF("java.vm.version");
		jstring vm_version_value = static_cast<jstring>(env->CallStaticObjectMethod(System, System_getProperty, vm_version_name));
		char* cvm_version_value = Util::jstringTostring(env, vm_version_value);
		env->DeleteLocalRef(vm_version_name);
		env->DeleteLocalRef(vm_version_value);
		double version = atof(cvm_version_value);
		free(cvm_version_value);
		//Messageprint::printinfo("tag", "vm_version_value:%lf", version);
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
