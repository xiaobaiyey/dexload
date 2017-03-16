#include "pch.h"
#include "PluginDex.h"
#include "util.h"
#include "Messageprint.h"
#include "dexload.h"
#include "Artvm.h"
#include "Davlikvm.h"
#include <sys/stat.h>
#include "loaddata.h"


hidden jboolean PluginDex::loadDex(JNIEnv* env,jobject obj,jstring dexpath)
{
	PluginDex* plugin_dex = new PluginDex(env, dexpath);
	if (plugin_dex == nullptr)
	{
		LOGE("%s %s", __FUNCTION__, "init fail");
		return JNI_FALSE;
	}
	return plugin_dex->startload();
}

/**
 * \brief load others dex
 * \param classLoader java object Class loader
 */
hidden PluginDex::PluginDex(JNIEnv* env, jstring dexpath): env(env)
{
	DexFilePath = Util::jstringTostring(env, dexpath);
	jobject context = getApplicationContext();
	jclass ContextClass = env->GetObjectClass(context);
	//context
	jmethodID getClassLoader = env->GetMethodID(ContextClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
	ClassLoader = env->CallObjectMethod(context, getClassLoader);
	jmethodID getFilesDir = env->GetMethodID(ContextClass, "getFilesDir", "()Ljava/io/File;");
	jobject File_obj = env->CallObjectMethod(context, getFilesDir);
	jclass FileClass = env->GetObjectClass(File_obj);
	jmethodID getAbsolutePath = env->GetMethodID(FileClass, "getAbsolutePath", "()Ljava/lang/String;");
	jstring data_file_dir = static_cast<jstring>(env->CallObjectMethod(File_obj, getAbsolutePath));
	DataFileDir = Util::jstringTostring(env, data_file_dir);
	env->DeleteLocalRef(data_file_dir);
	env->DeleteLocalRef(FileClass);
	env->DeleteLocalRef(File_obj);

	jmethodID getApplicationInfo = env->GetMethodID(ContextClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
	jobject ApplicationInfo_obj = env->CallObjectMethod(context, getApplicationInfo);
	jclass ApplicationInfoClass = env->GetObjectClass(ApplicationInfo_obj);
	jfieldID nativeLibraryDir_field = env->GetFieldID(ApplicationInfoClass, "nativeLibraryDir", "Ljava/lang/String;");
	jstring nativeLibraryDir = static_cast<jstring>(env->GetObjectField(ApplicationInfo_obj, nativeLibraryDir_field));
	DataNativeDir = Util::jstringTostring(env, nativeLibraryDir);
	env->DeleteLocalRef(nativeLibraryDir);

	jmethodID getPackageName = env->GetMethodID(ContextClass, "getPackageName", "()Ljava/lang/String;");
	jstring PackageNameJNI = static_cast<jstring>(env->CallObjectMethod(context, getPackageName));
	PackageName = Util::jstringTostring(env, PackageNameJNI);
	PackageNames = PackageName;
	env->DeleteLocalRef(PackageNameJNI);

	env->DeleteLocalRef(context);
	env->DeleteLocalRef(ContextClass);
	//初始化
	char* codedir = new char[256];
	char* optdir = new char[256];
	memset(codedir, 0, 256);
	memset(optdir, 0, 256);
	sprintf(codedir, "%s/%s", DataFileDir, "code");
	sprintf(optdir, "%s/%s", DataFileDir, "optdir");
	if (access(optdir, F_OK) == -1)
	{
		mkdir(optdir, 505);
		chmod(optdir, 505);
	}
	if (access(codedir, F_OK) == -1)
	{
		mkdir(codedir, 505);
		chmod(codedir, 505);
	}
}

jobject PluginDex::getApplicationContext() const
{
	jclass localClass = env->FindClass("android/app/ActivityThread");
	jmethodID getapplication = env->GetStaticMethodID(localClass, "currentApplication", "()Landroid/app/Application;");
	if (getapplication != nullptr)
	{
		jobject application = env->CallStaticObjectMethod(localClass, getapplication);
	
		return application;
	}
	else
	{
		env->ExceptionClear();
	}
	return nullptr;
}

hidden jboolean PluginDex::startload()
{
	//check file
	if (access(DexFilePath,F_OK) == -1)
	{
		Messageprint::printerror("PluginDex", "check dex !!!!");
		return JNI_FALSE;
	}

	jclass DexFile = env->FindClass("dalvik/system/DexFile");//ClassName[1] dalvik/system/DexFile
	jfieldID mCookie;
	std::string cookietype = Util::getmCookieType(env);

	mCookie = env->GetFieldID(DexFile, "mCookie", cookietype.c_str());
	jmethodID openDexFileNative = nullptr;
	MethodSign method_sign = Util::getMehodSign(env, "dalvik.system.DexFile", "loadDex");
	//for art
	if (isArt)
	{
		openDexFileNative = env->GetStaticMethodID(DexFile, "loadDex", method_sign.sign.c_str());
		//get and hook some function
		Artvm::hookstart();
		Artvm::hookEnable(false);
	}
	else
	{
		openDexFileNative = env->GetStaticMethodID(DexFile, "loadDex", method_sign.sign.c_str());
		// get and hook some function
		davlik_ = Davlik::initdvm();
	}
	return  DexFileLoaddex(openDexFileNative, cookietype.c_str());
}

hidden jboolean PluginDex::DexFileLoaddex(jmethodID loadDex, const char* cooketype)
{
	jclass DexFile = env->FindClass("dalvik/system/DexFile");//ClassName[1] dalvik/system/DexFile
	char* coptdir = new char[256];
	memset(coptdir, 0, 256);
	//data/data/packageName/files/opt/文件夹
	sprintf(coptdir, "%s/%s", DataFileDir, "plugindir");
	if (access(coptdir, F_OK) == -1)
	{
		mkdir(coptdir, 505);
		chmod(coptdir, 505);
	}
	if (strcmp(cooketype, "I") == 0)
	{
		char* copt_string = new char[256];
		memset(copt_string, 0, 256);
		char* mmoat = getoatdex(DexFilePath);
		sprintf(copt_string, "%s/%s", coptdir, mmoat);
		if (isArt)
		{
			jstring oufile = env->NewStringUTF(copt_string);
			jstring infile = env->NewStringUTF(DexFilePath);
			Artvm::setPluginDexAndOat(DexFilePath, mmoat, PackageName);
			Artvm::needDex2oat(DexFilePath, copt_string, sdk_int, DataNativeDir, "", mmoat,1);
			jobject dexfileobj = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, 0);
			loaddata::makeDexElements(env, ClassLoader, dexfileobj);
			env->DeleteLocalRef(infile);
			env->DeleteLocalRef(oufile);
		}
		else
		{
			if (davlik_->initOk)
			{
				jint mcookie;

				if (davlik_->loaddex(DexFilePath, mcookie))

				{
					jobject dexfileobj = loaddata::makeDexFileObject(env, mcookie, DataFileDir);
					loaddata::makeDexElements(env, ClassLoader, dexfileobj);
				}
				//load fail
				else
				{
					Messageprint::printinfo("loaddex", "load fail");
					return  JNI_FALSE;
				}
			}
			//init fail
			else
			{
				Messageprint::printerror("loaddex", "init dvm fail");
				return  JNI_FALSE;
			}
		}
		delete[] copt_string;
	}
	else if (strcmp(cooketype, "J") == 0)
	{
		char* copt_string = new char[256];
		memset(copt_string, 0, 256);
		//only art
		char* mmoat = getoatdex(DexFilePath);
		sprintf(copt_string, "%s/%s", coptdir, mmoat);
		jstring oufile = env->NewStringUTF(copt_string);
		jstring infile = env->NewStringUTF(DexFilePath);
		Artvm::setPluginDexAndOat(DexFilePath, mmoat, PackageName);
		Artvm::needDex2oat(DexFilePath, copt_string, sdk_int, DataNativeDir, "", mmoat, 1);
		jobject dexfileobj = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, 0);
		loaddata::makeDexElements(env, ClassLoader, dexfileobj);
		env->DeleteLocalRef(infile);
		env->DeleteLocalRef(oufile);
		delete[] copt_string;
		
	}
	else if (strcmp(cooketype, "Ljava/lang/Object;") == 0)
	{
		char* copt_string = new char[256];
		memset(copt_string, 0, 256);
		//only art
		char* mmoat = getoatdex(DexFilePath);
		sprintf(copt_string, "%s/%s", coptdir, mmoat);
		jstring oufile = env->NewStringUTF(copt_string);
		jstring infile = env->NewStringUTF(DexFilePath);
		Artvm::setPluginDexAndOat(DexFilePath, mmoat, PackageName);
		Artvm::needDex2oat(DexFilePath, copt_string, sdk_int, DataNativeDir, "", mmoat, 1);
		jobject dexfileobj = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, 0);
		loaddata::makeDexElements(env, ClassLoader, dexfileobj);
		env->DeleteLocalRef(infile);
		env->DeleteLocalRef(oufile);
		delete[] copt_string;
	}
	Artvm::hookEnable(true);
	return JNI_TRUE;
}


hidden char* PluginDex::getoatdex(const char* path)
{
	char* data = strdup(path);
	char* index = strrchr(data, '/') + 1;
	return index;
}
