#include "MetadataExtractionReadAsYouGo.h"
#include <iostream>

int main(int argc, char* argv[])
{
	versionInformationMap versionInfo;
	const char* filename = nullptr;
	if (argv[1])
	{
		filename = (const char*)argv[1];
	}
	else
	{
		//filename = "C:\\Users\\AMalik\\source\\repos\\MetaDataExtractionReadAsYouGo\\Debug\\MetaDataExtractionReadAsYouGo.exe";
		filename = "C:\\Windows\\system32\\hostname.exe";
		//filename = "\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Tools\\MSVC\\14.26.28801\\bin\\Hostx86\\x86\\clang_rt.asan_dynamic-i386.dll";
		//filename = "\\Users\\AMalik\\AppData\\Local\\Microsoft\\Teams\\current\\ffmpeg.dll";
	}
	
	//MetadataEx extractor("C:\\Windows\\system32\\hostname.exe");
	//MetadataEx extractor("\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\mingw32\\bin\\libwinpthread-1.dll");
	//MetadataEx extractor("\\Program Files(x86)\\Microsoft Visual Studio\\2019\\Professional\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\mingw32\\bin\\libgcc_s_dw2-1.dll");
	//MetadataEx extractor("C:\\Users\\AMalik\\source\\repos\\MetaDataExtractionReadAsYouGo\\Debug\\MetaDataExtractionReadAsYouGo.exe");
	MetadataEx extractor(filename);
	if (extractor.getVersionInformation(versionInfo))
	{
		auto originalFileName = versionInfo[ITEM_ID_VERSION_RESOURCE_ORIGINAL_FILE_NAME];
		auto companyName = versionInfo[ITEM_ID_VERSION_RESOURCE_COMPANY_NAME];
		auto productName = versionInfo[ITEM_ID_VERSION_RESOURCE_PRODUCT_NAME];
		auto productVersion = versionInfo[ITEM_ID_VERSION_RESOURCE_PRODUCT_VERSION];
		auto fileVersion = versionInfo[ITEM_ID_VERSION_RESOURCE_FILE_VERSION];
		auto subsystem = versionInfo[ITEM_ID_VERSION_RESOURCE_SUBSYSTEM];

		std::cout << std::endl;
		std::wcout << "Original Filename is [" << originalFileName << "].\n";
		std::wcout << "Company Name is      [" << companyName << "].\n";
		std::wcout << "Product Name is      [" << productName << "].\n";
		std::wcout << "Product Version is   [" << productVersion << "].\n";
		std::wcout << "File Version is      [" << fileVersion << "].\n";
		std::wcout << "SubSystem is         [" << subsystem << "].\n";
	}

	return 0;
}