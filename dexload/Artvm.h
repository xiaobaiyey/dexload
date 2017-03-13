#pragma once
class Artvm
{
private:
	static int artmyfstat(int, struct stat*);
	static ssize_t artmyread(int fd, void* des, size_t request);
	static ssize_t artmywrite(int, const void*, size_t);
	static void* artmymmap(void*, size_t, int, int, int, off_t);
	static int artmymprotect(const void*, size_t, int);
	static int artmymunmap(void*, size_t);
	static int artmyopen(const char* pathname, int flags, ...);
	static ssize_t artmy__read_chk(int fd, void* buf, size_t count, size_t buf_size);
	static int artmyfork();
	static int artpremyexecv(const char* name, char*const * argv);

public:
	static void setdexAndoat(const char* dex, const char* oat);
	static void hookstart();
	static void hookEnable(bool isenable);
	static bool makedex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir);


};
