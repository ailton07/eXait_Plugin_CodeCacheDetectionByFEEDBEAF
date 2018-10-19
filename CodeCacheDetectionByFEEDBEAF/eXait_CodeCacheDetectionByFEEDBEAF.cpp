// CodeCacheDetectionByCode.cpp : Defines the entry point for the console application.
//
// WinDBG
// pin.exe -- F:\Binarios\CodeCacheDetectionByCode.exe
// On x32dbg
// findallmem 01211000,90 90 50 58
// s - b 0 L ? 80000000 90 90 50 58

#include<stdlib.h>
#include "stdio.h"

// Origem: https://msdn.microsoft.com/pt-br/library/s58ftw19.aspx
#include <windows.h> // for EXCEPTION_ACCESS_VIOLATION
#include <excpt.h>
#include <vector>
#include "MemUpdateMapInformations.h"

#include <string.h>

// De acordo com:
// https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf
// Signature can be certain code or data
// #define padrao 1

// ---------- start of eXait header modifications
#define DllExport extern "C" __declspec(dllexport)
DllExport char* GetPluginName(void);
DllExport char* GetPluginDescription(void);
DllExport int DoMyJob(void);

char* GetPluginName(void)
{
	static char PluginName[] = "CodeCacheDetectionByFEEDBEAF";
	return PluginName;
}

char* GetPluginDescription(void)
{
	static char MyDescription[] = "This plugin implements a search function to search for the code pattern FEEDBEAF.";
	return MyDescription;
}
// ---------- end of eXait header modifications


unsigned long getPageContent(unsigned long *p) {
	__try {
		//printf("%x\n", *p);
		return *p;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return NULL;
	}
}

int main(int argc, char** argv) {
	printf("\nSearching for PIN signature 0xfeedbeaf\n");

	std::vector<MEMPAGE> pageVector = GetPageVector();
	int signatureCount = 0;
	int pagecount = (int)pageVector.size();

	for (int i = 0; i < pagecount - 1; i++) {
		auto & currentPage = pageVector.at(i);

		if (getPageContent(reinterpret_cast<unsigned long *>(currentPage.mbi.BaseAddress)) == 0xfeedbeaf) {
			signatureCount++;
		}
	}

	printf("Signature count: %d\n", signatureCount);

	if (signatureCount > 0) {
		printf("PIN found\n");
	}
	else {
		printf("PIN not found\n");
	}

	system("pause");

	return 0;
}

int DoMyJob(void)
{
	printf("\nSearching for PIN signature 0xfeedbeaf\n");

	std::vector<MEMPAGE> pageVector = GetPageVector();
	int signatureCount = 0;
	int pagecount = (int)pageVector.size();
	unsigned long * lastOcorrencia = 0;

	for (int i = 0; i < pagecount - 1; i++) {
		auto & currentPage = pageVector.at(i);

		if (getPageContent(reinterpret_cast<unsigned long *>(currentPage.mbi.BaseAddress)) == 0xfeedbeaf) {
			lastOcorrencia = reinterpret_cast<unsigned long *>(currentPage.mbi.BaseAddress);
			signatureCount++;
		}
	}

	printf("Signature count: %d\n", signatureCount);

	if (signatureCount > 0) {
		printf("PIN found\n 0x%x\n", lastOcorrencia);
		return 1;
	}
	return 0;
}