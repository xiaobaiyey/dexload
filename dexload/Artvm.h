#pragma once
struct ArmDex2oatArg
{
	char* DEXPATH;
	char* OATPATH;
	char* NATIVEPATH;
	int SDKINT;
	char* PACKAGENAME;
	char* DEXNAME;
	char* OATNAME;
	int TYPE;
};
//for mmap oat file
struct OatHeader {
	unsigned char  magic[4];
	unsigned char  version[4];
	uint  adler32Checksum;
	uint  instructionSet;
	uint  instructionSetFeatures;
	uint  dexFileCount;
	uint  executableOffset;
	uint  interpreterToInterpreterBridgeOffset;
	uint  interpreterToCompiledCodeBridgeOffset;
	uint  jniDlsymLookupOffset;
	uint  quickGenericJniTrampolineOffset;
	uint  quickImtConflictTrampolineOffset;
	uint  quickResolutionTrampolineOffset;
	uint  quickToInterpreterBridgeOffset;
	uint  imagePatchDelta;											// The image relocated address delta
	uint  imageFileLocationOatChecksum;					// Adler-32 checksum of boot.oat's header
	uint  imageFileLocationOatDataBegin;				// The virtual address of boot.oat's oatdata section
	uint  keyValueStoreSize;										// The length of key_value_store
};
struct OatDexFileBefore
{
	uint32_t dex_file_location_size_;
	const char* dex_file_location_data_;//stop here
};
struct OatDexFileAfter
{
	uint32_t dex_file_location_checksum_;
	uint32_t dex_file_offset_;
	uint32_t class_offsets_offset_;
	uint32_t lookup_table_offset_;
};

class Artvm
{
private:
	static int artmyfstat(int, struct stat*);
	static ssize_t artmyread(int fd, void* des, size_t request);
	static void* artmymmap(void*, size_t, int, int, int, off_t);
	static int artmymprotect(const void*, size_t, int);
	static int artmymunmap(void*, size_t);
	static int artmyopen(const char* pathname, int flags, ...);
	static int artmyfork();
	static int artmyexecv(const char* name, char*const * argv);
	static bool makedex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir, const char* packageName, const char* dexName, const char* oatName, int TYPE);
	static void* startselfDex2oat(void* args);
public:
	static void setdexAndoat(const char* dex, const char* oat);
	static void hookstart();
	static void hookEnable(bool isenable);
	static void needDex2oat(const char* DEX_PATH, const char* OAT_PATH, int sdk_int, const char* NativeLibDir,const char* dexName,const char* oatName,int TYPE);
	static void setPluginDexAndOat(const char* dexfilePath, const char* oat, const char*packageName);
	//

};
