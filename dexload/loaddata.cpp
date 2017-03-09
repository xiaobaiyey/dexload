#include "pch.h"
#include "loaddata.h"
#include "util.h"
#include "Messageprint.h"
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <cstdio>
#include <dirent.h>;
#include <sys/stat.h>
#include <dlfcn.h>
#include "Hook.h"
#include <string>
#include <cstdlib>
#include "dexload.h"
#include "Davlik.h"
char* PackageFilePath;
char* PackageNames;

char* NativeLibDir;
//for dvm
static Davlik* dvm_davlik;


loaddata::loaddata()
{
}


loaddata::~loaddata()
{
}

void loaddata::run(JNIEnv* env, jobject obj, jobject ctx)
{
	jclass ActivityThread = env->FindClass("android/app/ActivityThread");
	jmethodID currentActivityThread = env->GetStaticMethodID(ActivityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
}


void loaddata::attachContextBaseContext(JNIEnv* env, jobject obj, jobject ctx)
{
	//获取data/data/packageName/File文件夹
	// //6.0为/data/user/0/packagename/files/目录
	jclass ApplicationClass = env->GetObjectClass(ctx);
	jmethodID getFilesDir = env->GetMethodID(ApplicationClass, "getFilesDir", "()Ljava/io/File;");
	jobject File_obj = env->CallObjectMethod(ctx, getFilesDir);
	jclass FileClass = env->GetObjectClass(File_obj);
	jmethodID getAbsolutePath = env->GetMethodID(FileClass, "getAbsolutePath", "()Ljava/lang/String;");
	jstring data_file_dir = static_cast<jstring>(env->CallObjectMethod(File_obj, getAbsolutePath));
	const char* cdata_file_dir = Util::jstringTostring(env, data_file_dir);
	//release
	env->DeleteLocalRef(data_file_dir);
	env->DeleteLocalRef(File_obj);
	env->DeleteLocalRef(FileClass);

	//NativeLibraryDir 获取lib所在文件夹
	jmethodID getApplicationInfo = env->GetMethodID(ApplicationClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
	jobject ApplicationInfo_obj = env->CallObjectMethod(ctx, getApplicationInfo);
	jclass ApplicationInfoClass = env->GetObjectClass(ApplicationInfo_obj);
	jfieldID nativeLibraryDir_fied = env->GetFieldID(ApplicationInfoClass, "nativeLibraryDir", "Ljava/lang/String;");
	jstring nativeLibraryDir = static_cast<jstring>(env->GetObjectField(ApplicationInfo_obj, nativeLibraryDir_fied));
	NativeLibDir = Util::jstringTostring(env, nativeLibraryDir);
	//释放
	env->DeleteLocalRef(nativeLibraryDir);
	env->DeleteLocalRef(ApplicationInfoClass);
	env->DeleteLocalRef(ApplicationInfo_obj);

	//获取apk 所在路径 方法getPackageResourcePath
	jmethodID getPackageResourcePath = env->GetMethodID(ApplicationClass, "getPackageResourcePath", "()Ljava/lang/String;");
	jstring mPackageFilePath = static_cast<jstring>(env->CallObjectMethod(ctx, getPackageResourcePath));
	const char* cmPackageFilePath = Util::jstringTostring(env, mPackageFilePath);
	PackageFilePath = const_cast<char*>(cmPackageFilePath);
	env->DeleteLocalRef(mPackageFilePath);

	//获取包名
	jmethodID getPackageName = env->GetMethodID(ApplicationClass, "getPackageName", "()Ljava/lang/String;");
	jstring PackageName = static_cast<jstring>(env->CallObjectMethod(ctx, getPackageName));
	const char* packagename = Util::jstringTostring(env, PackageName);
	PackageNames = (char*)packagename;
	env->DeleteLocalRef(PackageName);

	//重点 拿到ClassLoader
	jmethodID getClassLoader = env->GetMethodID(ApplicationClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
	jobject classLoader = env->CallObjectMethod(ctx, getClassLoader);

	char codePath[256] = {0};
	sprintf(codePath, "%s/%s", cdata_file_dir, "code");
	//导出dex文件并获取个数或者获取已经导出dex文件个数；
	int dexnums = ExtractFile(env, ctx, codePath);
	//free(&codePath);
	if (dexnums <= 0)
	{
		Messageprint::printinfo("loaddex", "");
		return;
	}
	//加载dex 

	jclass DexFile = env->FindClass("dalvik/system/DexFile");
	jfieldID mCookie;
	std::string cookietype = Util::getmCookieType(env);
	//针对mCookie 值的类型不同不对版本进行区分 
	mCookie = env->GetFieldID(DexFile, "mCookie", cookietype.c_str());

	MethodSign method_sign = Util::getMehodSign(env, "dalvik.system.DexFile", "loadDex");
	//get loadDex file Methodid 
	jmethodID openDexFileNative = nullptr;
	//Messageprint::printinfo(__FUNCTION__, "over here:%d", __LINE__);
	//for dvm
	if (isArt)
	{
		openDexFileNative = env->GetStaticMethodID(DexFile, "loadDex", method_sign.sign.c_str());
	}
	else
	{
		dvm_davlik = Davlik::initdvm();
	}
	loaddex(env, openDexFileNative, cdata_file_dir, method_sign.argSize, dexnums, cookietype.c_str(), classLoader);
}

/*
*env
*ctx Context Application Context
*path /data/data/packageName/files/code dir
*/
int loaddata::ExtractFile(JNIEnv* env, jobject ctx, const char* path)
{
	if (access(path, F_OK) == -1)
	{
		mkdir(path, 505);
		chmod(path, 505);
		//拿到AAssetManager
		AAssetManager* mgr;
		jclass ApplicationClass = env->GetObjectClass(ctx);
		jmethodID getAssets = env->GetMethodID(ApplicationClass, "getAssets", "()Landroid/content/res/AssetManager;");
		jobject Assets_obj = env->CallObjectMethod(ctx, getAssets);
		mgr = AAssetManager_fromJava(env, Assets_obj);
		if (mgr == nullptr)
		{
			Messageprint::printerror("ExtractFile", "AAssetManager_fromJava fail");
			return 0;
		}
		//历遍根assets目录
		AAssetDir* dirs = AAssetManager_openDir(mgr, "");
		//AAsset* asset = AAssetManager_open(mgr, "dump.dex", AASSET_MODE_STREAMING);
		const char* FileName;
		int i = 0;
		while ((FileName = AAssetDir_getNextFileName(dirs)) != nullptr)
		{
			if (strstr(FileName, "encrypt") != nullptr && strstr(FileName, "dex") != nullptr)
			{
				AAsset* asset = AAssetManager_open(mgr, FileName, AASSET_MODE_STREAMING);
				FILE* file;
				void* buffer;
				int numBytesRead;
				if (asset != nullptr)
				{
					char filePath[256] = {0};
					sprintf(filePath, "%s/%s", path, FileName);
					file = fopen(filePath, "wb");
					//       int bufferSize = AAsset_getLength(asset); 
					//       LOGI("buffersize is %d",bufferSize);
					buffer = malloc(4096);
					while (true)
					{
						numBytesRead = AAsset_read(asset, buffer, 4096);
						if (numBytesRead <= 0)
							break;
						fwrite(buffer, numBytesRead, 1, file);
					}
					free(buffer);
					fclose(file);
					AAsset_close(asset);
					i = i + 1;
					chmod(filePath, 493);
				}
				else
				{
					Messageprint::printerror("ExtractFile", "AAsset is null :%s", FileName);
				}
			}
		}
		return i;
	}
	else//获取dex数目
	{
		DIR* dir = opendir(path);
		struct dirent* direntp;
		int i = 0;
		if (dir != nullptr)
		{
			for (;;)
			{
				direntp = readdir(dir);
				if (direntp == nullptr) break;
				//printf("%s\n", direntp->d_name);
				if (strstr(direntp->d_name, "encrypt") != nullptr && strstr(direntp->d_name, "dex") != nullptr)
				{
					i = i + 1;
				}
			}
			closedir(dir);
			return i;
		}
		Messageprint::printinfo("ExtractFile", "dir existed");
	}

	return 0;
}


//------------------------------hook----------------------------------start
static bool stophook = false;
static int testoatfd = 0;

//------------------------------hook------------------------------------end
//此处开始加载dex 参数比较多
/*2017年3月6日11:10:08测试正常
 *openDexFileNative 方法指针
 *opt 优化输出目录
 *argSize openDexFileNative方法参数个数
 *dexnums 共多少个dex
 *cooketype 决定调用那个方法 
 *classLoader Application.getClassLoader();
 */
void loaddata::loaddex(JNIEnv* env, jmethodID loadDex, const char* data_filePath, int argSize, int dexnums, const char* cooketype, jobject/*for android 7.0*/ classLoader)
{
	//2017年3月6日11:10:22 fix
	// for android 7.0  argsize=5
	jclass DexFile = env->FindClass("dalvik/system/DexFile");
	char* coptdir = new char[256];
	memset(coptdir, 0, 256);
	//data/data/packageName/files/opt/文件夹
	sprintf(coptdir, "%s/%s", data_filePath, "optdir");
	if (access(coptdir, F_OK) == -1)
	{
		mkdir(coptdir, 505);
		chmod(coptdir, 505);
	}
	//释放内存
	//delete[] coptdir;

	stophook = false;
	//针对7.0 
	if (argSize == 5)
	{
		for (int i = 0; i < dexnums; ++i)
		{
			//dex文件路径
			char* codePath = new char[256];
			//优化输出路径
			char* copt_string = new char[256];
			memset(copt_string, 0, 256);
			memset(codePath, 0, 256);
			sprintf(codePath, "%s/%s/%s%d.%s", data_filePath, "code", "encrypt", (i), "dex");
			sprintf(copt_string, "%s/%s%d.%s", coptdir, "lib", (i), "so");
			jstring oufile = env->NewStringUTF(copt_string);
			jstring infile = env->NewStringUTF(codePath);
			//oat 优化
			if (makedex2oat(codePath, copt_string))
			{
				//loadDex(String sourcePathName, String outputPathName,int flags, ClassLoader loader, DexPathList.Element[] elements) and get DexFile Object
				jobject dexfileobj = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, nullptr, classLoader, nullptr);
				makeDexElements(env, classLoader, dexfileobj);
			}
			else
			{
				Messageprint::printerror("dex2oat", "make fail");
			}
			//release
			env->DeleteLocalRef(oufile);
			delete[] codePath;
			delete[] copt_string;
		}
	}
	//for android 4 -6
	else if (argSize == 3)
	{
		if (strcmp(cooketype, "I") == 0)
		{
			// art or dvm android 4.4 have art 
			for (int i = 0; i < dexnums; ++i)
			{
				char* codePath = new char[256];
				char* copt_string = new char[256];
				memset(copt_string, 0, 256);
				memset(codePath, 0, 256);
				// dex 文件路径 data/data/packageName/files/code/encrypt.x.dex;
				sprintf(codePath, "%s/%s/%s%d.%s", data_filePath, "code", "encrypt", (i), "dex");
				sprintf(copt_string, "%s/%s%d.%s", coptdir, "lib", (i), "so");
				//for art
				if (isArt)
				{
					jstring oufile = env->NewStringUTF(copt_string);
					jstring infile = env->NewStringUTF(codePath);
					//加载dex 并拿到cookie值
					if (makedex2oat(codePath, copt_string))
					{
						jobject dexfileobj = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, 0);
						makeDexElements(env, classLoader, dexfileobj);
					}
					else
					{
						Messageprint::printerror("makedex2oat", "make fail");
					}
					//释放优化
					env->DeleteLocalRef(infile);
					env->DeleteLocalRef(oufile);
					env->DeleteLocalRef(oufile);
					env->DeleteLocalRef(infile);
				}
				//for dvm
				else
				{
					if (dvm_davlik->initOk)
					{
						jint mcookie;

						if (dvm_davlik->loaddex(codePath, mcookie))
						{
							jobject dexfileobj = makeDexFileObject(env, mcookie, data_filePath);
							makeDexElements(env, classLoader, dexfileobj);
						}
						//load fail
						else
						{
							Messageprint::printinfo("loaddex", "load fail");
						}
					}
					//init fail
					else
					{
						Messageprint::printerror("loaddex", "init dvm fail");
					}
				}
				delete[] codePath;
				delete[] copt_string;
			}
		}
		else if (strcmp(cooketype, "J") == 0)
		{
			//only art
			for (int i = 0; i < dexnums; ++i)
			{
				char* codePath = new char[256];
				char* copt_string = new char[256];
				memset(copt_string, 0, 256);
				memset(codePath, 0, 256);
				// dex file path  data/data/packageName/files/code/encrypt.x.dex;
				sprintf(codePath, "%s/%s/%s%d.%s", data_filePath, "code", "encrypt", (i), "dex");
				sprintf(copt_string, "%s/%s%d.%s", coptdir, "lib", (i), "so");
				jstring oufile = env->NewStringUTF(copt_string);
				jstring infile = env->NewStringUTF(codePath);
				//dex2oat
				if (makedex2oat(codePath, copt_string))
				{
					jobject dexfileobj = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, 0);
					makeDexElements(env, classLoader, dexfileobj);
				}
				else
				{
					Messageprint::printerror("makedex2oat", "make fail");
				}

				//release

				env->DeleteLocalRef(oufile);
				env->DeleteLocalRef(infile);

				delete[] codePath;
				delete[] copt_string;
			}
		}
		//only art
		else if (strcmp(cooketype, "Ljava/lang/Object;") == 0)
		{
			for (int i = 0; i < dexnums; ++i)
			{
				char* codePath = new char[256];
				char* copt_string = new char[256];
				memset(copt_string, 0, 256);
				memset(codePath, 0, 256);
				// dex file path data/data/packageName/files/code/encrypt.x.dex;
				sprintf(codePath, "%s/%s/%s%d.%s", data_filePath, "code", "encrypt", (i), "dex");
				sprintf(copt_string, "%s/%s%d.%s", coptdir, "lib", (i), "so");
				jstring oufile = env->NewStringUTF(copt_string);
				jstring infile = env->NewStringUTF(codePath);
				//dex2oat
				if (makedex2oat(codePath, copt_string))
				{
					jobject dexFile = env->CallStaticObjectMethod(DexFile, loadDex, infile, oufile, 0);
					makeDexElements(env, classLoader, dexFile);
				}
				else
				{
					Messageprint::printerror("makedex2oat", "make fail");
				}
				env->DeleteLocalRef(oufile);
				env->DeleteLocalRef(infile);
				delete[] codePath;
				delete[] copt_string;
			}
		}
	}
	stophook = true;
	// start unhook open mmap 
}

jobject loaddata::makeDexFileObject(JNIEnv* env, jint cookie, const char* filedir)
{
	char* in = new char[256];
	char* out = new char[256];
	memset(in, 0, 256);
	memset(out, 0, 256);
	sprintf(in, "%s/%s/%s", filedir, "code", "mini.dex");
	sprintf(out, "%s/%s/%s", filedir, "optdir", "mini.odex");
	//写minidex
	dvm_davlik->writeminidex(in);

	jclass DexFileClass = env->FindClass("dalvik/system/DexFile");
	jmethodID init = env->GetMethodID(DexFileClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;I)V");
	jstring apk = env->NewStringUTF(in);
	jstring odex = env->NewStringUTF(out);
	jobject dexobj = env->NewObject(DexFileClass, init, apk, odex, 0);//暂时不用释放了

	jfieldID mCookie = env->GetFieldID(DexFileClass, "mCookie", "I");
	env->SetIntField(dexobj, mCookie, cookie);

	env->DeleteLocalRef(DexFileClass);
	env->DeleteLocalRef(apk);
	env->DeleteLocalRef(odex);
	delete[]in;
	delete[]out;
	return dexobj;
}

/*
 *make DexPathList$Element obj
 *
 *classLoader 
 *dexFileobj   DexFile object  from  loadDex
 */
hidden void loaddata::makeDexElements(JNIEnv* env, jobject classLoader, jobject dexFileobj)
{
	//Application.getClassLoader().getClass().getName()  = dalvik.system.PathClassLoader
	/*
	*PathClassLoader superClass BaseDexClassLoader
	*BaseDexClassLoader superClass  ClassLoader
	*/
	jclass PathClassLoader = env->GetObjectClass(classLoader);

	jclass BaseDexClassLoader = env->GetSuperclass(PathClassLoader);
	//release

	//get pathList fiedid
	jfieldID pathListid = env->GetFieldID(BaseDexClassLoader, "pathList", "Ldalvik/system/DexPathList;");
	jobject pathList = env->GetObjectField(classLoader, pathListid);

	//get DexPathList Class 
	jclass DexPathListClass = env->GetObjectClass(pathList);
	//get dexElements fiedid
	jfieldID dexElementsid = env->GetFieldID(DexPathListClass, "dexElements", "[Ldalvik/system/DexPathList$Element;");

	//get dexElement array value
	jobjectArray dexElement = static_cast<jobjectArray>(env->GetObjectField(pathList, dexElementsid));


	//get DexPathList$Element Class construction method and get a new DexPathList$Element object 
	jint len = env->GetArrayLength(dexElement);


	jclass ElementClass = env->FindClass("dalvik/system/DexPathList$Element");
	jmethodID Elementinit = env->GetMethodID(ElementClass, "<init>", "(Ljava/io/File;ZLjava/io/File;Ldalvik/system/DexFile;)V");
	jboolean isDirectory = JNI_FALSE;
	jobject element_obj = env->NewObject(ElementClass, Elementinit, nullptr, isDirectory, nullptr, dexFileobj);

	//Get dexElement all values and add  add each value to the new array
	jobjectArray new_dexElement = env->NewObjectArray(len + 1, ElementClass, nullptr);
	for (int i = 0; i < len; ++i)
	{
		env->SetObjectArrayElement(new_dexElement, i, env->GetObjectArrayElement(dexElement, i));
	}
	//then set dexElement Fied 

	env->SetObjectArrayElement(new_dexElement, len, element_obj);
	env->SetObjectField(pathList, dexElementsid, new_dexElement);

	env->DeleteLocalRef(element_obj);
	env->DeleteLocalRef(ElementClass);
	env->DeleteLocalRef(dexElement);
	env->DeleteLocalRef(DexPathListClass);
	env->DeleteLocalRef(pathList);
	env->DeleteLocalRef(BaseDexClassLoader);
	env->DeleteLocalRef(PathClassLoader);
}

hidden bool loaddata::makedex2oat(const char* DEX_PATH, const char* OAT_PATH)
{
	//if oat file exist retrun true
	if (access(OAT_PATH, F_OK) == -1)
	{
		std::string cmd;
		//DEX_PATH="/data/data/com.xiaobai.loaddextest/files/code/encrypt0.dex" 
		cmd.append("DEX_PATH=\"");
		cmd.append(DEX_PATH);
		cmd.append("\" ");

		//OAT_PATH="/data/local/tmp/test.so"   
		cmd.append("OAT_PATH=\"");
		cmd.append(OAT_PATH);
		cmd.append("\" ");

		//LD_PRELOAD="/data/app/com.catchingnow.icebox-1/lib/arm/libdexload.so"
		cmd.append("LD_PRELOAD=\"");
		char* paths = new char[256];
		memset(paths, 0, 256);
		sprintf(paths, "%s/libdexload.so", NativeLibDir);
		cmd.append(paths);
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

		Messageprint::printinfo("dex2oat", "cmd:%s", cmd.c_str());

		int optres = system(cmd.c_str());
		Messageprint::printinfo("dex2oat", "optres:%d", optres);
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
