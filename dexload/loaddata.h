#pragma once
class loaddata
{
public:

	loaddata();
	~loaddata();
	static void run(JNIEnv* env, jobject obj, jobject ctx);
	static void attachContextBaseContext(JNIEnv* env, jobject obj, jobject ctx);
private:
	static int ExtractFile(JNIEnv* env, jobject ctx, const char* path);
	static void loaddex(JNIEnv* env, jmethodID openDexFileNative, const char* data_filePath, int argSize, int dexnums, const char* cooketype, jobject/*for android 7.0*/ classLoader);
	static void makeDexElements(JNIEnv* env, jobject classLoader, jobject file);
	static bool makedex2oat(const char* DEX_PATH, const char* OTA_PATH);
	static jobject makeDexFileObject(JNIEnv* env, jint cookie, const char* filedir);
};
