#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <tuple>
#include <variant>
#include <functional>
#include "File.h"

//namespace uc
//{
    enum class PEfileType
    {
        PE_TYPE_NONE  = 0x0,
        PE_TYPE_32BIT = 0x1,
        PE_TYPE_64BIT = 0x2
    };

    typedef struct
    {
		IMAGE_RESOURCE_DIRECTORY spDir;
		std::shared_ptr<IMAGE_RESOURCE_DIRECTORY_ENTRY> spEntry;
    }resource_tree_level_t;

	typedef struct
	{
		ULONG datadirRva;
		ULONG offset;
		resource_tree_level_t levels[3];
		std::unique_ptr<BYTE[]> spDataBuffer;
		DWORD dataBufferSize;
	} resource_section_info_t;

using version_value_t = std::pair<std::wstring, std::wstring>;
using version_values_t = std::vector<version_value_t>;
using optionalHeader = std::variant<IMAGE_OPTIONAL_HEADER32*, IMAGE_OPTIONAL_HEADER64*>;

template <typename intT>
static constexpr void ALIGN_32BIT_BOUNDRY(intT& i)
{
	i = (i + 0x3) & (~0x3);
}

#define VERINFO_PARSE_ERR           "VersionInfo parse error: "
#define PE_PARSE_ERR				"Not a valid PE: "

#define VS_VERSION_STRING			(L"VS_VERSION_INFO")
#define VS_VERSION_STRING_LEN		(sizeof (VS_VERSION_STRING))/sizeof(wchar_t)

#define FILE_INFO_STRING            (L"StringFileInfo")
#define FILE_INFO_STRING_LEN		sizeof (FILE_INFO_STRING)/sizeof(wchar_t)

#define VAR_FILE_INFO_STRING        (L"VarFileInfo")
#define VAR_FILE_INFO_STRING_LEN    sizeof (VAR_FILE_INFO_STRING)/sizeof(wchar_t)

#define ENG_LANG_CODE_STRING        (L"09")
#define ENG_LANG_CODE_STRING_LEN	(sizeof (ENG_LANG_CODE_STRING)-sizeof(wchar_t))/sizeof(wchar_t)

#define SEEK_AND_READ(offset,buf,type,num,success)\
do{\
    m_pSeek(offset);\
    buf = std::make_unique<type[]>(num);\
    success = m_pRead((BYTE*)buf.get(), sizeof(type)*num);\
}while(0)

#define SEEK_AND_READ1(offset,buf,type,num,success)\
do{\
    m_pSeek(offset);\
    success = m_pRead((BYTE*)&buf, sizeof(type)*num);\
}while(0)

#define SEEK_AND_READ_SHARED(offset,buf,type,num,success)\
do{\
    m_pSeek(offset);\
    buf = std::make_shared<type>();\
    success = m_pRead((BYTE*)buf.get(), sizeof(type));\
}while(0)

#pragma pack(1)
	typedef struct version_info_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t key[VS_VERSION_STRING_LEN];
		BYTE* opaque;
	} version_info_t;
#pragma pack()

#pragma pack(1)
	typedef struct string_file_info_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t key[FILE_INFO_STRING_LEN];
		char* opaque;
	} string_file_info_t;
#pragma pack()

#pragma pack(1)
	typedef struct string_tbl_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t key[8];
		char* opaque;
	} string_tbl_t;
#pragma pack()

#pragma pack(1)
	typedef struct string_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t opaque[1];
	} string_t;
#pragma pack()

    class PEParser
    {
        public:
			using pSeek_t = std::function<bool(long)>;
			using pRead_t = std::function<bool(void*, const DWORD)>;

			PEParser(
				const std::string& fileName,
				pSeek_t pSeek,
				pRead_t pRead);

			bool parseResourceDir(
				const LPWSTR resourceId,
				resource_section_info_t& pResourceSection);

            bool parseVersionInfo(
				const resource_section_info_t& pResourceSection,
				version_values_t& vi) const;

			const uint32_t getSubsystem() const;

        private:
            static constexpr uint32_t MAX_NUM_SECTIONS = 100;
			static constexpr uint32_t MAX_NUM_DATA_DIRECTORIES = 20;
			static constexpr uint32_t MAX_NUM_SUBSYSTEMS = 20;
					   
            std::string m_fileName;
            PEfileType m_flags;
            uint32_t m_numSections;
			uint32_t m_numDataDirectories;
			uint32_t m_subSystem;
			uint32_t m_bufSize;
			pSeek_t  m_pSeek;
			pRead_t  m_pRead;

			IMAGE_DOS_HEADER m_spDosHdr;                                /* Dos header */
			IMAGE_NT_HEADERS m_spPeHdr;                                 /* PE header */
            IMAGE_FILE_HEADER* m_pFileHdr;				                /* File header */
			optionalHeader m_pOptionalHdr;                              /* Optional Header */
			std::unique_ptr<IMAGE_SECTION_HEADER[]> m_spSectionTable;   /* Section table */
            
        private:
			void parsePeFileType(
				const PEfileType PEfileTypeFlags);

			bool getResourceSection(
				resource_section_info_t& pResourceSection) const;
    };
//}

