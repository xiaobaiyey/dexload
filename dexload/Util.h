#pragma once
#include <string>

struct MethodSign
{
	size_t argSize;
	std::string sign;
};

class Util
{
public:
	Util();
	~Util();
	static  char* jstringTostring(JNIEnv* env, jstring str);
	static  std::string getType(char* type);
	static MethodSign getMehodSign(JNIEnv* env, const char* jclassName, const char* jmethodName);
	static std::string getmCookieType(JNIEnv* env);
	static  jobject newFile(JNIEnv*env, const char* filePath);
};

