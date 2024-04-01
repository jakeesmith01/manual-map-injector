#include "injector.h"

void __stdcall shellcode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE hProc, const char* dllFilePath) {
	BYTE*					pSourceData		= nullptr;
	IMAGE_NT_HEADERS*		pOldNtHeader	= nullptr;
	IMAGE_OPTIONAL_HEADER*	pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER*		pOldFileHeader	= nullptr;
	BYTE*					pTargetBase		= nullptr;

	if (!GetFileAttributesA(dllFilePath)) {
		printf("File doesn't exist\n");
		return false;
	}

	std::ifstream File(dllFilePath, std::ios::binary | std::ios::ate);

	//check if it was able to open the file
	if (File.fail()) {
		printf("Opening file failed: %X\n", (DWORD)File.rdstate());
		return false;
	}

	//check the size of the file
	auto fileSize = File.tellg();
	if (fileSize < 0x1000) {
		printf("File size is invalid.\n");
		File.close();
		return false;
	}

	//allocating memory for the file
	pSourceData = new BYTE[static_cast<UINT_PTR>(fileSize)];

	//check if pSourceData was allocated in to the memory
	if (!pSourceData) {
		printf("Memory allocation failed.\n");
		File.close();
		return false;
	}

	//move to the beginning of the file
	File.seekg(0, std::ios::beg);

	//read the data from the file in to pSourceData
	File.read(reinterpret_cast<char*>(pSourceData), fileSize);
	File.close();

	//check file format
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_magic != 0x5A4D) {
		printf("Invalid file\n");
		delete[] pSourceData;
		return false;
	}

	//Points to the new NT_HEADER
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSourceData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSourceData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("Invalid platform.\n");
		delete[] pSourceData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		printf("Invalid platform.\n");
		delete[] pSourceData;
		return false;
	}
#endif

	//Allocate memory in the target process
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase) {
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase) {
			printf("Memory allocation failed 0x%X\n", GetLastError());
			delete[] pSourceData;
			return false;
		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, pSectionHeader++) {
		if (pSectionHeader->SizeOfRawData) {
			//writes raw data section to memory location in target process
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSourceData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				printf("Failed to map sections: 0x%X\n", GetLastError());
				delete[] pSourceData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSourceData, &data, sizeof(data));

	//writes pSourceData buffer in to memory of target proc
	WriteProcessMemory(hProc, pTargetBase, pSourceData, 0x1000, nullptr);

	//bye bye pSource
	delete[] pSourceData;

	//allocate some space in target proc's memory for some shellcode shenanigans
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		printf("Memory allocation failed: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	//writing shellcode in to target proc's memory
	WriteProcessMemory(hProc, pShellcode, shellcode, 0x1000, nullptr);

	//creating a thread to execute our freshly cooked shellcode
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if (!hThread) {
		printf("Thread creation failed: 0x % X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);

	//waits for the remote thread to finish execution
	HINSTANCE hCheck = NULL; //this will hold the handle to the module after being loaded in to target proc
	while (!hCheck) { //when hCheck not null, indicates the module has been loaded
		MANUAL_MAPPING_DATA dataChecked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &dataChecked, sizeof(dataChecked), nullptr);
		hCheck = dataChecked.hMod; 
		Sleep(10);
	}
	
	//free up the space allocated for pShellcode cause we done here 
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;
}

//macros for reloc types
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

//checks if 64 bit, if not then 32 bit
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) { return; }

	BYTE* pBase		= reinterpret_cast<BYTE*>(pData);
	auto* pOpt		= &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA		= pData->pLoadLibraryA;
	auto _GetProcAddress	= pData->pGetProcAddress;
	auto _DllMain			= reinterpret_cast<f_DLL_ENTRYPOINT>(pBase + pOpt->AddressOfEntryPoint);

	//the difference between preferred base address of mod and the actual base address where mod was loaded
	BYTE* locDelta = pBase - pOpt->ImageBase;
	if (locDelta) { //if 0, mod was loaded at its pref base addr somehow
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) { return; }

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		//while pRelocData points to a virtual address, must relocate
		while (pRelocData->VirtualAddress) {
			UINT amtOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			//This consists of 2 bytes -- the high 12 bits are the offset of the relocation, low 4 are flags for type of relocation
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != amtOfEntries; i++, pRelativeInfo++) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(locDelta); 
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock); //movin on
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescriptor->Name) {
			char* currMod = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
			HINSTANCE hDll = _LoadLibraryA(currMod); 

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

			//if originalfirstthunk isnt defined , must use firstthunk
			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; pThunkRef++, pFuncRef++) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else { //import by name
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}

			pImportDescriptor++;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; pCallback && *pCallback; pCallback++) { //iterate thru all tls callbacks -> call each w params
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase); //setting hMod to address of the loaded module

}