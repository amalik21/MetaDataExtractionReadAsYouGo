#pragma once
#include <Windows.h>
#include <unordered_map>

#include "PEParser.h"
#include "File.h"

static constexpr const wchar_t* ORIGINAL_FILENAME_STRING{ L"OriginalFilename" };
static constexpr const wchar_t* COMPANY_NAME_STRING{ L"CompanyName" };
static constexpr const wchar_t* FILE_VERSION_STRING{ L"FileVersion" };
static constexpr const wchar_t* PRODUCT_NAME_STRING{ L"ProductName" };
static constexpr const wchar_t* PRODUCT_VERSION_STRING{ L"ProductVersion" };

typedef enum
{
	ITEM_ID_VERSION_RESOURCE_ORIGINAL_FILE_NAME = 1,
	ITEM_ID_VERSION_RESOURCE_COMPANY_NAME,
	ITEM_ID_VERSION_RESOURCE_PRODUCT_NAME,
	ITEM_ID_VERSION_RESOURCE_PRODUCT_VERSION,
	ITEM_ID_VERSION_RESOURCE_FILE_VERSION,
	ITEM_ID_VERSION_RESOURCE_SUBSYSTEM
} VersionInfoItemIDs;
using versionInformationMap = std::unordered_map<VersionInfoItemIDs, std::wstring>;

inline static void CHECK_RET_CODE(bool ret, const char* err)
{
	if (!ret)
	{
		throw std::runtime_error("Failed to parse: " + std::string(err));
	}
}

inline static bool searchVersionInfoByName(
	const version_values_t& versionInfo,
	const std::wstring& key,
	std::wstring& value)
{
	bool found{ false };
	for (auto& i : versionInfo)
	{
		if (wcsncmp(i.first.c_str(), key.c_str(), key.size()) == 0)
		{
			value = i.second;
			found = true;
			break;
		}
	}

	return found;
}

inline static void UPDATE_VERSION_INFO(
	version_values_t& versionInfo,
	const std::wstring& attributeName,
	VersionInfoItemIDs attributeID,
	versionInformationMap& entity)
{
	std::wstring attributeValue;
	if (searchVersionInfoByName(versionInfo, attributeName, attributeValue))
	{
		entity.emplace(attributeID, attributeValue);
	}
	else
	{
		std::wcout << "Failed to find attribute " << attributeName <<
			" in VS_VERSIONINFO resource." << std::endl;
	}
}

class MetadataEx
{
public:
	MetadataEx(std::string file)
		: m_file(file)
	{};

	bool getVersionInformation(
		versionInformationMap& entity);

	File m_file;
};
