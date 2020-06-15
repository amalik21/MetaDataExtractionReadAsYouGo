//#include "pch.h"
#include "PEParser.h"
#include <cassert>

//namespace cu
//{
	PEParser::PEParser(
		const std::string& fileName,
		std::function<bool(long)> pSeek,
		std::function<bool(void*, const DWORD)> pRead)
		: 
		m_fileName{},
		m_spDosHdr{},
		m_spPeHdr{},
		m_pFileHdr{},
		m_spSectionTable{},
		m_numDataDirectories{},
		m_numSections{},
		m_subSystem{},
		m_bufSize{},
		m_flags{ PEfileType::PE_TYPE_NONE }
     {
		if (!fileName.size() || !pSeek || !pRead)
		{
			throw std::runtime_error("Invalid arguments to parser.");
		}

		auto success{ false };
		auto currentOffset{ 0u };

		m_fileName = fileName;
		m_pSeek = pSeek;
		m_pRead = pRead;

		SEEK_AND_READ1(currentOffset, m_spDosHdr, IMAGE_DOS_HEADER, 1, success);

		// 'MZ' header check
		success = success && (m_spDosHdr.e_magic == IMAGE_DOS_SIGNATURE);
		if (success)
		{
			currentOffset += m_spDosHdr.e_lfanew;
			SEEK_AND_READ1(currentOffset, m_spPeHdr, IMAGE_NT_HEADERS, 1, success);
			success = (m_spPeHdr.Signature == IMAGE_NT_SIGNATURE);
		}
		else
		{
			std::cout << m_fileName << " is not a valid executable. Skipping." << std::endl;
		}

		if (success)
		{
			if (m_spPeHdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				parsePeFileType(PEfileType::PE_TYPE_32BIT);
			}
			else
			{
				parsePeFileType(PEfileType::PE_TYPE_64BIT);
			}

			currentOffset += sizeof(m_spPeHdr.Signature) + sizeof(IMAGE_FILE_HEADER) +
				m_spPeHdr.FileHeader.SizeOfOptionalHeader;
			SEEK_AND_READ(currentOffset, m_spSectionTable, IMAGE_SECTION_HEADER, m_numSections, success);
		}
		else
		{
			throw std::runtime_error(PE_PARSE_ERR "PE Signature not found.");
		}

		return;
	}

	template <typename T>
	static bool constexpr validate_numeric_value(T value, const T max, const T min = 0)
	{
		return (value > min && value < max);
	}

	void PEParser::parsePeFileType(
		const PEfileType PEfileTypeFlags)
	{
		m_flags = PEfileTypeFlags;
		if (PEfileTypeFlags == PEfileType::PE_TYPE_32BIT)
		{
			m_pOptionalHdr = (IMAGE_OPTIONAL_HEADER32*)(&m_spPeHdr.OptionalHeader);
			auto pOptionalHdr = std::get<IMAGE_OPTIONAL_HEADER32*>(m_pOptionalHdr);
			m_numDataDirectories = pOptionalHdr->NumberOfRvaAndSizes;
			m_subSystem = pOptionalHdr->Subsystem;
		}
		else if (PEfileTypeFlags == PEfileType::PE_TYPE_64BIT)
		{
			m_pOptionalHdr = (IMAGE_OPTIONAL_HEADER64*)(&m_spPeHdr.OptionalHeader);
			auto pOptionalHdr = std::get<IMAGE_OPTIONAL_HEADER64*>(m_pOptionalHdr);
			m_numDataDirectories = pOptionalHdr->NumberOfRvaAndSizes;
			m_subSystem = pOptionalHdr->Subsystem;
		}
		else
		{
			throw std::runtime_error
			{
				"Neither 32-bit not 64-bit."
			};
		}
		
		m_numSections = m_spPeHdr.FileHeader.NumberOfSections;
		std::cout << "Subsystem = " << m_subSystem << std::endl;
		std::cout << "Number of Sections = " << m_numSections << std::endl;
		std::cout << "NumDataDirectories = " << m_numDataDirectories << std::endl;

		return;
	}

	const uint32_t PEParser::getSubsystem() const
    {
        return m_subSystem;
    }

	bool PEParser::getResourceSection(
		resource_section_info_t& pResourceSection) const
	{
		auto success{ false };

		if (!m_numSections ||
			(
				!std::holds_alternative<IMAGE_OPTIONAL_HEADER32*>(m_pOptionalHdr) &&
				!std::holds_alternative<IMAGE_OPTIONAL_HEADER64*>(m_pOptionalHdr)
			))
		{
			throw std::runtime_error("The PE is not yet parsed !");
		}

		if (m_numDataDirectories > IMAGE_DIRECTORY_ENTRY_RESOURCE)
		{
			auto rva{ 0ul };
			if (std::holds_alternative<IMAGE_OPTIONAL_HEADER64*>(m_pOptionalHdr))
			{
				assert(m_flags == PEfileType::PE_TYPE_64BIT);
				rva = std::get<IMAGE_OPTIONAL_HEADER64*>(m_pOptionalHdr)->DataDirectory
					[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
			}
			else
			{
				assert(m_flags == PEfileType::PE_TYPE_32BIT);
				rva = std::get<IMAGE_OPTIONAL_HEADER32*>(m_pOptionalHdr)->DataDirectory
					[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
			}

			for (auto i{ 0u }; i < m_numSections; i++)
			{
				const auto& pSectionTable = m_spSectionTable;
				auto sectionEnd = (pSectionTable[i].Misc.VirtualSize >
					pSectionTable[i].SizeOfRawData) ?
					pSectionTable[i].Misc.VirtualSize :
					pSectionTable[i].SizeOfRawData;

				if ((rva >= pSectionTable[i].VirtualAddress) &&
					(rva < pSectionTable[i].VirtualAddress + sectionEnd))
				{
#ifdef _DEBUG
					char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
					strncpy_s(sectionName,
						(char*)(pSectionTable[i].Name), IMAGE_SIZEOF_SHORT_NAME);
					sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
					std::cout << "SectionName = " << sectionName << std::endl;
#endif
					assert(rva == pSectionTable[i].VirtualAddress);
					pResourceSection.datadirRva = rva;
					pResourceSection.offset = pSectionTable[i].PointerToRawData;
					return true;
				}
			}

			std::cout << "Error: Resource section header not found.\n";
		}

		return success;
	}

	bool PEParser::parseResourceDir(
		const LPWSTR resourceId,
		resource_section_info_t& pResourceSection)
	{
		auto success{ false };

		if (!resourceId)
		{
			throw std::runtime_error("Invalid arguments to parserResourceDir.");
		}

		if (this->getResourceSection(pResourceSection))
		{
            std::shared_ptr<IMAGE_RESOURCE_DIRECTORY_ENTRY> pTempDirEntry;

			// PointerToRawData: This is the file-based offset of where the resource section resides in PE.
			// VirtualAddress: This is the RVA to where the loader should map the section.
			auto rootDirOffset = pResourceSection.offset;
			auto L0_Offset = rootDirOffset;

			SEEK_AND_READ1(L0_Offset, pResourceSection.levels[0].spDir, IMAGE_RESOURCE_DIRECTORY, 1, success);
			if (!success)
			{
				throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
			}

			// Locate required id type directory entry in root dir
			auto found{ false };
			auto L0EntryOffset{ L0_Offset + sizeof(IMAGE_RESOURCE_DIRECTORY) };

			for (auto i{ 0 };
				i < (pResourceSection.levels[0].spDir.NumberOfIdEntries +
					pResourceSection.levels[0].spDir.NumberOfNamedEntries);
				i++)
			{
			    SEEK_AND_READ_SHARED(L0EntryOffset, pTempDirEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);
				L0EntryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

				if (pTempDirEntry &&
					pTempDirEntry.get()->DataIsDirectory &&
					pTempDirEntry.get()->Id == (WORD)((ULONG_PTR)resourceId))
				{
					found = true;
					break;
				}
			}

			if (!found)
			{
				std::cout << "Info: Resource " << resourceId << " not found in the EXE.\n";
				success = false;
			}
			else
			{
				// Level 1
				auto L1_Offset = rootDirOffset + pTempDirEntry.get()->OffsetToDirectory;
				SEEK_AND_READ1(L1_Offset, pResourceSection.levels[1].spDir, IMAGE_RESOURCE_DIRECTORY, 1, success);

				if (!success)
				{
					throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
				}

				auto L1EntryOffset{ L1_Offset + sizeof(IMAGE_RESOURCE_DIRECTORY) };
				for (auto i{ 0 };
					i < (pResourceSection.levels[1].spDir.NumberOfIdEntries +
						pResourceSection.levels[1].spDir.NumberOfNamedEntries);
					i++)
				{
					// Level 2
					SEEK_AND_READ_SHARED(L1EntryOffset, pTempDirEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);
					L1EntryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

					assert(pTempDirEntry != NULL);
					assert(pTempDirEntry.get()->DataIsDirectory == 1); // level 2 points to DataDirectory
					if (pTempDirEntry && pTempDirEntry.get()->DataIsDirectory == 1)
					{
						auto L2_Offset = rootDirOffset + pTempDirEntry.get()->OffsetToDirectory;
						SEEK_AND_READ1(L2_Offset, pResourceSection.levels[2].spDir,
							IMAGE_RESOURCE_DIRECTORY, 1, success);

						if (!success)
						{
							throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
						}

						auto L2EntryOffset{ L2_Offset + sizeof(IMAGE_RESOURCE_DIRECTORY) };
						for (i = 0;
							i < (pResourceSection.levels[2].spDir.NumberOfIdEntries +
								pResourceSection.levels[2].spDir.NumberOfNamedEntries);
							i++)
						{
							// Level 3
							std::cout << "Level 3 -->\n";
							std::cout << "Num Ids = " << pResourceSection.levels[2].spDir.NumberOfIdEntries << std::endl;
							std::cout << "Num Named = " << pResourceSection.levels[2].spDir.NumberOfNamedEntries << std::endl;

							SEEK_AND_READ_SHARED(L2EntryOffset, pTempDirEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);
							L2EntryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

							assert(pTempDirEntry && pTempDirEntry.get()->DataIsDirectory == 0); // level 3 points to Data (leaf node)

							std::unique_ptr<IMAGE_RESOURCE_DATA_ENTRY[]> spData;
							SEEK_AND_READ(rootDirOffset + (ULONG)(pTempDirEntry.get()->OffsetToData), spData,
								IMAGE_RESOURCE_DATA_ENTRY, 1, success);

							if (spData)
							{
								// Size of data must be non-zero
								pResourceSection.dataBufferSize = spData.get()->Size;
								assert(pResourceSection.dataBufferSize > 0);

								auto dataOffset{ spData.get()->OffsetToData - pResourceSection.datadirRva };
								SEEK_AND_READ(rootDirOffset + dataOffset, pResourceSection.spDataBuffer,
									BYTE, pResourceSection.dataBufferSize, success);
								break;
							}
						}

						if (!pResourceSection.spDataBuffer)
						{
							std::cout << "Unable to extract data for resource Id [" << resourceId << "]\n";
						}
						else
						{
							std::cout << "Data size is: " << pResourceSection.dataBufferSize << std::endl;
						}
					}
				}
			}
		}

		return success;
	}

    bool PEParser::parseVersionInfo(
		const resource_section_info_t& pResourceSection,
		version_values_t& vi) const
    {
		auto found{ false };
		if (vi.empty())
		{
			if (!pResourceSection.spDataBuffer || !pResourceSection.dataBufferSize)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "ResourceDirectory is not already populated.");
			}

			auto versionInfoSize{ pResourceSection.dataBufferSize };
			auto pVersionInfo{ (version_info_t*)(pResourceSection.spDataBuffer.get()) };
			auto success = pVersionInfo && pVersionInfo->key && pVersionInfo->key[0];
			if (!success)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "VersionInfo key is Null or empty.");
			}

			success = (wcsncmp(pVersionInfo->key, VS_VERSION_STRING, VS_VERSION_STRING_LEN) == 0);
			if (!success)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "VersionInfo key has unexpected value.");
			}

			/* Align it to 32 bit boundry */
			auto offset = offsetof(version_info_t, opaque);
			ALIGN_32BIT_BOUNDRY(offset);
			offset += pVersionInfo->val_length;
			ALIGN_32BIT_BOUNDRY(offset);

			auto tmp = (BYTE*)pVersionInfo + offset;
			auto pFileInfo = (string_file_info_t*)tmp;

			while (true)
			{
				success = pFileInfo && pFileInfo->key && pFileInfo->key[0];
				if (!success)
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo key is Null or empty.");
				}

				if (pFileInfo->length > (sizeof(version_info_t) +
					(size_t)(tmp - pVersionInfo->opaque)))
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo length is too large.");
				}

				if (pFileInfo->length < sizeof(string_file_info_t))
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo length is too small.");
				}

				if (pFileInfo->length >= versionInfoSize)
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo length is too large.");
				}

				if (wcsncmp(pFileInfo->key, VAR_FILE_INFO_STRING, VAR_FILE_INFO_STRING_LEN) == 0)
				{
					offset = pFileInfo->length;
					ALIGN_32BIT_BOUNDRY(offset);
					pFileInfo = (string_file_info_t*)((BYTE*)pFileInfo + offset);
					continue;
				}
				else if (wcsncmp(pFileInfo->key, FILE_INFO_STRING, FILE_INFO_STRING_LEN) == 0)
				{
					break;
				}
				else
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "Unexpected FileInfo key encountered.");
				}
			}

			auto currentSize = offsetof(string_file_info_t, opaque);
			ALIGN_32BIT_BOUNDRY(currentSize);
			while (currentSize < pFileInfo->length)
			{
				auto pTable = (string_tbl_t*)((BYTE*)pFileInfo + currentSize);

				currentSize += pTable->length;
				ALIGN_32BIT_BOUNDRY(currentSize);
				if (pTable->length < sizeof(string_tbl_t))
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is too small.");
				}

				if (versionInfoSize < (ULONG)(((BYTE*)pTable - (BYTE*)pVersionInfo) +
					pTable->length))
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is too large.");
				}

				if (NULL == pTable->key + 2)
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "String Table key is not valid.");
				}

				printf("%S and %S\n", pTable->key, pTable->key + 2);
				std::cout << "ENG_LANG_CODE_STRING_LEN = " << ENG_LANG_CODE_STRING_LEN << "\n";

				/* We are interested only in english language version info */
				if (wcsncmp(pTable->key + ENG_LANG_CODE_STRING_LEN, ENG_LANG_CODE_STRING, ENG_LANG_CODE_STRING_LEN) != 0)
				{
					/* Hack for some bad behaving apps */
					if (wcsncmp(pTable->key + ENG_LANG_CODE_STRING_LEN, (L"00"), ENG_LANG_CODE_STRING_LEN) != 0)
						continue;
				}

				auto currentStringTableSize = offsetof(string_tbl_t, opaque);
				ALIGN_32BIT_BOUNDRY(currentStringTableSize);
				while (currentStringTableSize < pTable->length)
				{
					auto pString = (string_t*)((BYTE*)pTable + currentStringTableSize);
					if (pString->length < sizeof(string_t))
					{
						throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is not valid.");
					}

					if (versionInfoSize < (ULONG)(((BYTE*)pString - (BYTE*)pVersionInfo) +
						pString->length))
					{
						throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is not large.");
					}

					currentStringTableSize += pString->length;
					ALIGN_32BIT_BOUNDRY(currentStringTableSize);

					if (pString->type == 0)
					{
						continue;
					}

					auto key = (wchar_t*)pString->opaque;
					offset = offsetof(string_t, opaque);
					offset += (ULONG)(wcslen(key) * sizeof(wchar_t) + sizeof(wchar_t));
					ALIGN_32BIT_BOUNDRY(offset);
					auto value = (wchar_t*)((BYTE*)pString + offset);

					vi.emplace_back(std::make_pair(std::wstring(key), std::wstring(value)));
					found = true;
				}
			}
		}
		else
		{
			found = true;
		}

        return found;
    }
	
#ifdef _DEBUG
	const char* getNameFromId(int Id)
	{
		static const char* ResourceTypes[] = {
			"0",
			"CURSOR",
			"BITMAP",
			"ICON",
			"MENU",
			"DIALOG",
			"STRING",
			"FONTDIR",
			"FONT",
			"ACCELERATORS",
			"RCDATA",
			"MESSAGETABLE",
			"GROUP_CURSOR",
			"13",
			"GROUP_ICON",
			"15",
			"VERSION",
			"DLGINCLUDE",
			"18",
			"PLUGPLAY",
			"VXD",
			"ANICURSOR",
			"ANIICON",
			"HTML",
			"MANIFEST"
		};

		if (Id > 24)
			return nullptr;
		return ResourceTypes[Id];
	}
#endif
//}
