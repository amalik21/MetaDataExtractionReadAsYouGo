// MetadataExtractorC++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include "MetadataExtractionReadAsYouGo.h"

/********************* MetadataEx ******************/
bool MetadataEx::getVersionInformation(
	versionInformationMap& entity)
{
	version_values_t versionInfo;
	uint32_t subsystem;
	auto ret{ false };

	try
	{
		resource_section_info_t resourceSectionInfo{};


		std::cout << "Parsing file: " << m_file.getName() << " ==> " << std::endl;
		ret = m_file.open();
		CHECK_RET_CODE(ret, "openFile failed");
		
		PEParser parser(m_file.getName(),
			std::bind(&File::seekStart, &m_file, std::placeholders::_1),
			std::bind(&File::read, &m_file, std::placeholders::_1, std::placeholders::_2));
		
		ret = ret && parser.parseResourceDir(RT_VERSION, resourceSectionInfo);
		CHECK_RET_CODE(ret, "parseResourceDir failed");

		ret = ret && parser.parseVersionInfo(resourceSectionInfo, versionInfo);
		CHECK_RET_CODE(ret, "parseVersionInfo failed");

		subsystem = parser.getSubsystem();
	}

	catch (const std::exception & ex)
	{
		std::cout << "Caught exception: " << ex.what() << std::endl;
		return false;
	}

	if (!versionInfo.empty())
	{
		UPDATE_VERSION_INFO(versionInfo, std::wstring(ORIGINAL_FILENAME_STRING),
			ITEM_ID_VERSION_RESOURCE_ORIGINAL_FILE_NAME, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(COMPANY_NAME_STRING),
			ITEM_ID_VERSION_RESOURCE_COMPANY_NAME, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(PRODUCT_NAME_STRING),
			ITEM_ID_VERSION_RESOURCE_PRODUCT_NAME, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(PRODUCT_VERSION_STRING),
			ITEM_ID_VERSION_RESOURCE_PRODUCT_VERSION, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(FILE_VERSION_STRING),
			ITEM_ID_VERSION_RESOURCE_FILE_VERSION, entity);

		entity.emplace(ITEM_ID_VERSION_RESOURCE_SUBSYSTEM, std::to_wstring(subsystem));
	}

	return ret;
}
