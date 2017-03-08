#include "pch.h"
#include "Messageprint.h"
#include <cstdio>
#define LOG_BUF_SIZE 1024

Messageprint::Messageprint()
{
}


Messageprint::~Messageprint()
{
}

void Messageprint::printerror(const char* tag, const char* fmt, ...)
{
	va_list ap;
	char buf[LOG_BUF_SIZE];

	va_start(ap, fmt);
	vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
	va_end(ap);
	__android_log_write(ANDROID_LOG_ERROR, tag, buf);
}

void Messageprint::printinfo(const char* tag, const char* fmt, ...)
{
	va_list ap;
	char buf[LOG_BUF_SIZE];

	va_start(ap, fmt);
	vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
	va_end(ap);
	__android_log_write(ANDROID_LOG_INFO, tag, buf);
}

void Messageprint::printverbose(const char* tag, const char* fmt, ...)
{
	va_list ap;
	char buf[LOG_BUF_SIZE];

	va_start(ap, fmt);
	vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
	va_end(ap);
	__android_log_write(ANDROID_LOG_VERBOSE, tag, buf);
}

void Messageprint::printwarn(const char* tag, const char* fmt, ...)
{
	va_list ap;
	char buf[LOG_BUF_SIZE];

	va_start(ap, fmt);
	vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
	va_end(ap);
	__android_log_write(ANDROID_LOG_WARN, tag, buf);
}

void Messageprint::printdebug(const char* tag, const char* fmt, ...)
{
	va_list ap;
	char buf[LOG_BUF_SIZE];

	va_start(ap, fmt);
	vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
	va_end(ap);
	__android_log_write(ANDROID_LOG_DEBUG, tag, buf);
}