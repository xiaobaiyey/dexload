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


public:
	static void setdexAndoat(const char* dex, const char* oat);
	static void hookstart();
	static void hookEnable(bool isenable);

};
