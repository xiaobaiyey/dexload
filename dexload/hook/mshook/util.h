#ifndef HOOK_UTIL_H_
#define HOOK_UTIL_H_
#if defined(__i386__) || defined(__x86_64__)
#include <unistd.h>

extern int find_name(pid_t pid, const char *name,const  char *libn, unsigned long *addr);
extern int find_libbase(pid_t pid, const char *libn, unsigned long *addr);
#endif
#endif
