#include "pch.h"
#include "Util.h"
#include "Messageprint.h"


Util::Util()
{
}


Util::~Util()
{
}

hidden char* Util::jstringTostring(JNIEnv* env, jstring str)
{
	char* rtn = nullptr;
	jclass clsstring = env->FindClass("java/lang/String");
	jstring strencode = env->NewStringUTF("utf-8");
	jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
	jbyteArray barr = (jbyteArray)env->CallObjectMethod(str, mid, strencode);
	jsize alen = env->GetArrayLength(barr);
	jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
	if (alen > 0)
	{
		rtn = (char*)malloc(alen + 1);
		memcpy(rtn, ba, alen);
		rtn[alen] = 0;
	}
	env->DeleteLocalRef(clsstring);
	env->DeleteLocalRef(strencode);
	env->ReleaseByteArrayElements(barr, ba, 0);
	return rtn;
}

/**
 * \brief Type conversion
 * \param type java 
 * \return 
 */
hidden std::string Util::getType(char* type)
{

	if (strcmp(type, "int") == 0)
	{
		return std::string("I");
	}
	else if (strcmp(type, "long") == 0)
	{
		return std::string("J");
	}
	else if (strcmp(type, "short") == 0)
	{
		return std::string("S");
	}
	else if (strcmp(type, "char") == 0)
	{
		return std::string("C");
	}
	else if (strcmp(type, "boolean") == 0)
	{
		return std::string("Z");
	}
	else if (strcmp(type, "float") == 0)
	{
		return std::string("F");
	}
	else if (strcmp(type, "double") == 0)
	{
		return std::string("D");
	}
	else if (strcmp(type, "void") == 0)
	{
		return std::string("V");
	}
	else if (type[0] == '[')
	{
		std::string str;
		if (type[1] == 'L')
		{
			char* typname = nullptr;
			typname = strdup(type);
			int length = strlen(typname) + 1;
			for (int i = 0; i < length; i++)
			{
				if (typname[i] == '.')
				{
					typname[i] = '/';
				}
			}
			str.append(typname);
			//2017年3月6日18:17:16 fix 对象数组 
			//str.append(";");
			return str;
		}
		return std::string(type);
	}
	else
	{
		std::string str;
		str.append("L");
		char* typname = nullptr;
		typname = strdup(type);
		int length = strlen(typname) + 1;
		for (int i = 0; i < length; i++)
		{
			if (typname[i] == '.')
			{
				typname[i] = '/';
			}
		}
		str.append(typname);
		str.append(";");
		return str;
	}
}

/**
 * \brief Get the signature of the java method
 * \param env 
 * \param jclassName 
 * \param jmethodName 
 * \return  signature of the method 
 */
hidden MethodSign Util::getMehodSign(JNIEnv* env, const char* jclassName, const char* jmethodName)
{
	jclass javaClass = env->FindClass("java/lang/Class");
	jmethodID forName = env->GetStaticMethodID(javaClass, "forName", "(Ljava/lang/String;)Ljava/lang/Class;");
	jstring DexFileClassName = env->NewStringUTF(jclassName);
	jobject DexFileClass = env->CallStaticObjectMethod(javaClass, forName, DexFileClassName);
	//调用getDeclaredMethods方法
	jmethodID getDeclaredMethods = env->GetMethodID(javaClass, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
	jobjectArray Methods = static_cast<jobjectArray>(env->CallObjectMethod(DexFileClass, getDeclaredMethods));
	jmethodID ClassgetName = env->GetMethodID(javaClass, "getName", "()Ljava/lang/String;");
	env->DeleteLocalRef(javaClass);


	//获取Method Class
	jclass MethodClass = env->FindClass("java/lang/reflect/Method");
	//获取Method 中的getParameterTypes 方法
	jmethodID getParameterTypes = env->GetMethodID(MethodClass, "getParameterTypes", "()[Ljava/lang/Class;");
	//获取Method 中的getReturnType 方法
	jmethodID getReturnType = env->GetMethodID(MethodClass, "getReturnType", "()Ljava/lang/Class;");
	//获取Method 中的getName 方法
	jmethodID MethodgetName = env->GetMethodID(MethodClass, "getName", "()Ljava/lang/String;");
	//历遍每一个方法
	env->DeleteLocalRef(MethodClass);

	jint len = env->GetArrayLength(Methods);
	std::string argStr("(");
	struct MethodSign sign;
	for (int i = 0; i < len; ++i)
	{
		jobject object = env->GetObjectArrayElement(Methods, i);
		jstring name = static_cast<jstring>(env->CallObjectMethod(object, MethodgetName));
		char* cname = Util::jstringTostring(env, name);
		if (strcmp(cname, jmethodName) == 0)
		{
			//获取openDexFileNative 方法的参数
			jobjectArray args = static_cast<jobjectArray>(env->CallObjectMethod(object, getParameterTypes));
			jint arglen = env->GetArrayLength(args);
			//循环获取每个参数的类型
			for (int j = 0; j < arglen; ++j)
			{
				jobject argClass = env->GetObjectArrayElement(args, j);
				//调用Class getName方法
				jstring argtypename = static_cast<jstring>(env->CallObjectMethod(argClass, ClassgetName));
				char* cargtypename = Util::jstringTostring(env, argtypename);
				//转换为参数类型
				argStr.append(getType(cargtypename));
				env->DeleteLocalRef(argClass);
				env->DeleteLocalRef(argtypename);
				free(cargtypename);
			}
			struct MethodSign sign;
			sign.argSize = arglen;

			//参数拼接完毕
			argStr.append(")");
			//拼接返回值
			jobject retClass = env->CallObjectMethod(object, getReturnType);
			jstring rettypename = static_cast<jstring>(env->CallObjectMethod(retClass, ClassgetName));
			char* crettypename = Util::jstringTostring(env, rettypename);
			argStr.append(getType(crettypename));
			//释放引用
			env->DeleteLocalRef(retClass);
			env->DeleteLocalRef(rettypename);
			free(crettypename);
			env->DeleteLocalRef(object);
			env->DeleteLocalRef(name);
			free(cname);
			env->DeleteLocalRef(Methods);
			sign.sign = argStr;
			//Messageprint::printinfo("opendexnative", "sign :%s", argStr.c_str());
			return sign;
		}
		//释放引用
		env->DeleteLocalRef(object);
		env->DeleteLocalRef(name);
		free(cname);
	}
	return sign;
}

/**
 * \brief get DexFile.mCookie Field
 * \param env 
 * \return Field tyoe
 */
hidden std::string Util::getmCookieType(JNIEnv* env)
{
	//原理同过java的反射拿到cookie 类型
	jclass javaClass = env->FindClass("java/lang/Class");
	jmethodID forName = env->GetStaticMethodID(javaClass, "forName", "(Ljava/lang/String;)Ljava/lang/Class;");
	jstring DexFileClassName = env->NewStringUTF("dalvik.system.DexFile");
	jobject DexFileClass = env->CallStaticObjectMethod(javaClass, forName, DexFileClassName);
	jmethodID getDeclaredField = env->GetMethodID(javaClass, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
	jstring mcookieName = env->NewStringUTF("mCookie");
	jobject mfield = env->CallObjectMethod(DexFileClass, getDeclaredField, mcookieName);

	jclass fieldClass = env->FindClass("java/lang/reflect/Field");
	jmethodID getTypeMethod = env->GetMethodID(fieldClass, "getType", "()Ljava/lang/Class;");

	jobject getTypeResultClass = env->CallObjectMethod(mfield, getTypeMethod);

	jmethodID getName = env->GetMethodID(javaClass, "getName", "()Ljava/lang/String;");
	jstring mcookieType = static_cast<jstring>(env->CallObjectMethod(getTypeResultClass, getName));
	char* type = jstringTostring(env, mcookieType);
	//Messageprint::printinfo("tag","type:%s",type);
	env->DeleteLocalRef(getTypeResultClass);
	env->DeleteLocalRef(mfield);
	env->DeleteLocalRef(DexFileClass);
	env->DeleteLocalRef(mcookieName);
	env->DeleteLocalRef(DexFileClassName);
	env->DeleteLocalRef(mcookieType);
	return getType(type);
}

hidden jobject Util::newFile(JNIEnv* env, const char* filePath)
{
	jclass File = env->FindClass("java/io/File");
	jmethodID init = env->GetMethodID(File, "<init>", "(Ljava/lang/String;)V");
	jstring filepaths = env->NewStringUTF(filePath);
	jobject obj = env->NewObject(File, init, filepaths);
	env->DeleteLocalRef(File);
	env->DeleteLocalRef(filepaths);
	return obj;
}
