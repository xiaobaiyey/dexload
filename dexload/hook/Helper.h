//
// VirtualApp Native Project
//

#ifndef NDK_LOG_H
#define NDK_LOG_H
#include <android/log.h>
#define TAG "jnitools"
#define FREE(ptr, org_ptr) { if ((void*) ptr != NULL && (void*) ptr != (void*) org_ptr) { free((void*) ptr); } }
#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
#define NATIVE_METHOD(func_ptr, func_name, signature) { func_name, signature, reinterpret_cast<void*>(func_ptr) }
#define ANDROID_JBMR2    18
#define ANDROID_L        21
#define ANDROID_N        24
#endif //NDK_LOG_H
