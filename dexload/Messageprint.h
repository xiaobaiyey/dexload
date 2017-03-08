#pragma once
class Messageprint
{
public:
	Messageprint();
	~Messageprint();
	/* ANDROID_LOG_ERROR*/
	static void printerror(const char* tag, const char* fmt, ...);
	/*ANDROID_LOG_INFO*/
	static void printinfo(const char* tag, const char* fmt, ...);
	/*ANDROID_LOG_VERBOSE*/
	static void printverbose(const char* tag, const char* fmt, ...);
	/* ANDROID_LOG_WARN*/
	static void printwarn(const char* tag, const char* fmt, ...);
	/* ANDROID_LOG_DEBUG*/
	static void printdebug(const char* tag, const char* fmt, ...);
	
};
