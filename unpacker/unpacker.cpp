//Include structures file from packer project
#include "../simple_pe_packer/structs.h"

//Unpacking algorithm
#include "lzo/lzo1z.h"

//Create function without prologue and epilogue
extern "C" void __declspec(naked) unpacker_main()
//extern "C" void  unpacker_main()  //only for check the stack size
{
	//Create prologue manually
	__asm
	{
		jmp next;
		ret 0xC;
	next:
		push ebp;
		mov ebp, esp;
		sub esp, 0x200;
		
		mov eax, 0x11111111;
		mov ecx, 0x22222222;
	}
	
	//Image loading address
	DWORD image_base;
	//First section relative address,
	//in which the packer stores its information
	//and packed data themselves
	DWORD rva_of_first_section;
	
	//These instructions are required only to
	//replace the addresses in unpacker builder with real ones
	__asm
	{
		mov image_base, eax;
		mov rva_of_first_section, ecx;
	}
	
	//Address of the variable,
	//which indicates if code was unpacked already
	DWORD* was_unpacked;

	__asm
	{
		//Trick to get address
		//of instruction following "call"
		call next2;
		add byte ptr [eax], al;
		add byte ptr [eax], al;
next2:
		//There is an address of first instruction
		//add byte ptr [eax], al
		//in eax
		pop eax;

		//Store this address
		mov was_unpacked, eax;

		//Check what is stored there
		mov eax, [eax];

		//If there is zero, then move to
		//the unpacker
		test eax, eax;
		jz next3;

		//If not, then finish the unpacker
		//and go to original entry point
		leave;
		jmp eax;

next3:
	}
	//Get pointer to structure with information
	//carefully prepared by packer
	const packed_file_info* info;
	//It is stored in the beginning
	//of packed file first section
	info = reinterpret_cast<const packed_file_info*>(image_base + rva_of_first_section);

	//Two LoadLibraryA and GetProcAddress function prototypes typedefs 
	typedef HMODULE (__stdcall* load_library_a_func)(const char* library_name);
	typedef INT_PTR (__stdcall* get_proc_address_func)(HMODULE dll, const char* func_name);
	typedef BOOL (__stdcall* free_library_func)(HMODULE hLibModule);

	//Read their addresses from packed_file_info structure
	//Loader puts them there for us
	load_library_a_func load_library_a;
	get_proc_address_func get_proc_address;
	free_library_func free_library;
	load_library_a = reinterpret_cast<load_library_a_func>(info->load_library_a);
	get_proc_address = reinterpret_cast<get_proc_address_func>(info->get_proc_address);
	free_library = reinterpret_cast<free_library_func>(info->free_library);
	
	//Create buffer on stack
	char buf[32];
	//kernel32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'nrek';
	*reinterpret_cast<DWORD*>(&buf[4]) = '23le';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'lld.';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//Load kernel32.dll library
	HMODULE kernel32_dll;
	kernel32_dll = load_library_a(buf);

	//VirtualAlloc function prototype typedef
	typedef LPVOID (__stdcall* virtual_alloc_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	//VirtualProtect function prototype typedef
	typedef LPVOID (__stdcall* virtual_protect_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	//VirtualFree function prototype typedef
	typedef LPVOID (__stdcall* virtual_free_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

	//VirtualAlloc
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Alau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'coll';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//Get VirtualAlloc function address
	virtual_alloc_func virtual_alloc;
	virtual_alloc = reinterpret_cast<virtual_alloc_func>(get_proc_address(kernel32_dll, buf));

	//VirtualProtect
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Plau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'etor';
	*reinterpret_cast<DWORD*>(&buf[12]) = 'tc';

	//Get VirtualProtect function address
	virtual_protect_func virtual_protect;
	virtual_protect = reinterpret_cast<virtual_protect_func>(get_proc_address(kernel32_dll, buf));

	//VirtualFree
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Flau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'eer';

	//Get VirtualFree function address
	virtual_free_func virtual_free;
	virtual_free = reinterpret_cast<virtual_free_func>(get_proc_address(kernel32_dll, buf));

	//Copy all packed_file_info structure fields, because
	//we will need them further, but we will overwrite the structure at "info" pointer soon
	packed_file_info info_copy;
	memcpy(&info_copy, info, sizeof(info_copy));

	//Pointer to the memory 
	//to store unpacked data
	LPVOID unpacked_mem;
	//Allocate the memory
	unpacked_mem = virtual_alloc(
		0,
		info->size_of_unpacked_data,
		MEM_COMMIT,
		PAGE_READWRITE);

	//Unpacked data size
	//(in fact, this variable is unnecessary)
	lzo_uint out_len;
	out_len = 0;

	//Unpack with LZO algorithm
	if (LZO_E_OK !=
		lzo1z_decompress(
			reinterpret_cast<const unsigned char*>(reinterpret_cast<DWORD>(info) + sizeof(packed_file_info)),
			info->size_of_packed_data,
			reinterpret_cast<unsigned char*>(unpacked_mem),
			&out_len,
			0)
		)
	{
		//If something goes wrong, but
		// naked function can not return;
	}
	
	
	//Pointer to DOS file header
	const IMAGE_DOS_HEADER* dos_header_org;
	//Pointer to file header
	IMAGE_FILE_HEADER* file_header_org;
	//Pointer to NT header
	IMAGE_NT_HEADERS* nt_headers_org;
	//Virtual address of sections header beginning
	DWORD offset_to_section_headers_org;
	//Calculate this address
	dos_header_org = reinterpret_cast<const IMAGE_DOS_HEADER*>(unpacked_mem);
	nt_headers_org = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<char *>(unpacked_mem) + dos_header_org->e_lfanew);
	file_header_org = &(nt_headers_org->FileHeader);
	//with this formula
	offset_to_section_headers_org = reinterpret_cast<DWORD>(unpacked_mem) + dos_header_org->e_lfanew + file_header_org->SizeOfOptionalHeader
		+ sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;
	
	//Pointer to DOS file header
	const IMAGE_DOS_HEADER* dos_header;
	//Pointer to file header
	IMAGE_FILE_HEADER* file_header;
	//Pointer to NT header
	IMAGE_NT_HEADERS* nt_headers;
	//Virtual address of sections header beginning
	DWORD offset_to_section_headers;
	//Calculate this address
	dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
	nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + dos_header->e_lfanew);
	file_header = &(nt_headers->FileHeader);
	//with this formula
	offset_to_section_headers = image_base + dos_header->e_lfanew + file_header->SizeOfOptionalHeader
		+ sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;

	PIMAGE_SECTION_HEADER section_header;
	section_header = IMAGE_FIRST_SECTION(nt_headers);
	//Null first section memory
	//This region matches the memory region,
	//which is occupied by all sections in original file
	memset(
		reinterpret_cast<void*>(image_base + rva_of_first_section),
		0,
		section_header->Misc.VirtualSize);

	//Let's change memory block attributes, in which
	//PE file and section headers are placed
	//We need write access
	DWORD old_protect;
	virtual_protect(reinterpret_cast<LPVOID>(image_base),
		rva_of_first_section,
		PAGE_READWRITE, &old_protect);

	//Get original entry point address
	DWORD original_ep;
	original_ep = nt_headers_org->OptionalHeader.AddressOfEntryPoint + image_base;

	//Write it to address stored in
	//was_unpacked variable
	*was_unpacked = original_ep;

	//Now we change section number
	//in PE file header to original
	file_header->NumberOfSections = file_header_org->NumberOfSections;
	//Restore AddressOfEntryPoint
	nt_headers->OptionalHeader.AddressOfEntryPoint = nt_headers_org->OptionalHeader.AddressOfEntryPoint;
	//Restore SizeOfImage
	nt_headers->OptionalHeader.SizeOfImage = nt_headers_org->OptionalHeader.SizeOfImage;
	//Copy filled header
	//to memory, where section headers are stored
	memcpy(reinterpret_cast<void*>(offset_to_section_headers), reinterpret_cast<void*>(offset_to_section_headers_org), sizeof(IMAGE_SECTION_HEADER) * (file_header->NumberOfSections));
	
	//Load all the sections data
	for(int i = 0; i < file_header->NumberOfSections; ++i, ++section_header)
	{
		//Copying sections data to the place in memory,
		//where they have to be placed
		memcpy(reinterpret_cast<void*>(image_base + section_header->VirtualAddress),
			reinterpret_cast<char*>(unpacked_mem) + section_header->PointerToRawData,
			section_header->SizeOfRawData);
	}

	//Size of directory table
	DWORD size_of_directories;
	size_of_directories = sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	//Calculate relative virtual address
	//of directory table beginning
	DWORD offset_to_directories_org;
	offset_to_directories_org = offset_to_section_headers_org - size_of_directories;
	//Calculate relative virtual address
	//of directory table beginning
	DWORD offset_to_directories;
	offset_to_directories = offset_to_section_headers - size_of_directories;
	//Restore the directorys 
	memcpy(reinterpret_cast<void*>(offset_to_directories), reinterpret_cast<void*>(offset_to_directories_org), size_of_directories);

	//Release memory with unpacked data,
	//we don't need it anymore
	virtual_free(unpacked_mem, 0, MEM_RELEASE);
	
	//Pointer to import directory
	IMAGE_DATA_DIRECTORY* import_dir;
	import_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_IMPORT);

	//If the file has imports
	if(import_dir->VirtualAddress)
	{
		//First descriptor virtual address
		IMAGE_IMPORT_DESCRIPTOR* descr;
		descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_dir->VirtualAddress + image_base);

		//List all descriptors
		//Last one is nulled
		while(descr->Name)
		{
			//Load the required DLL
			HMODULE dll;
			dll = load_library_a(reinterpret_cast<char*>(descr->Name + image_base));
			//Pointers to address table and lookup table
			DWORD* lookup, *address;
			//Take into account that lookup table may be absent,
			//as I mentioned at previous step
			lookup = reinterpret_cast<DWORD*>(image_base + (descr->OriginalFirstThunk ? descr->OriginalFirstThunk : descr->FirstThunk));
			address = reinterpret_cast<DWORD*>(descr->FirstThunk + image_base);

			//List all descriptor imports
			while(true)
			{
				//Till the first null element in lookup table
				DWORD lookup_value = *lookup;
				if(!lookup_value)
					break;

				//Check if the function is imported by ordinal
				if(IMAGE_SNAP_BY_ORDINAL32(lookup_value))
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value & ~IMAGE_ORDINAL_FLAG32)));
				else
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value + image_base + sizeof(WORD))));

				//Move to next element
				++lookup;
				++address;
			}
			//Move to next descriptor
			++descr;
		}
	}

	// Adjust base address of imported data
	ptrdiff_t locationDelta;
	locationDelta = (ptrdiff_t)(image_base - nt_headers->OptionalHeader.ImageBase);

	// Need relocation
	if (locationDelta)
	{
		//Pointer to relocation directory
		IMAGE_DATA_DIRECTORY* relocation_dir;
		relocation_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_BASERELOC);
		//If a file had relocations and it
		//was moved by the loader
		if (relocation_dir->VirtualAddress)
		{
			//Pointer to a first IMAGE_BASE_RELOCATION structure
			const IMAGE_BASE_RELOCATION* reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(relocation_dir->VirtualAddress + image_base);

			//List relocation tables
			while (reloc->VirtualAddress > 0)
			{
				//List all elements in a table
				for (unsigned long i = sizeof(IMAGE_BASE_RELOCATION); i < reloc->SizeOfBlock; i += sizeof(WORD))
				{
					//Relocation value
					WORD elem = *reinterpret_cast<const WORD*>(reinterpret_cast<const char*>(reloc) + i);
					//If this is IMAGE_REL_BASED_HIGHLOW relocation (there are no other in PE x86)
					if ((elem >> 12) == IMAGE_REL_BASED_HIGHLOW)
					{
						//Get DWORD at relocation address
						DWORD* value = reinterpret_cast<DWORD*>(image_base + reloc->VirtualAddress + (elem & ((1 << 12) - 1)));
						//Fix it like PE loader
						*value += locationDelta;
					}
				}
				//Go to next relocation table
				reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const char*>(reloc) + reloc->SizeOfBlock);
			}
		}

	}

	//Pointer to load configuration directory
	IMAGE_DATA_DIRECTORY* load_config_dir;
	load_config_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	//If file has load configuration directory
	if (load_config_dir->VirtualAddress)
	{
		//Get pointer to original load configuration directory
		const IMAGE_LOAD_CONFIG_DIRECTORY32* cfg = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY32*>(load_config_dir->VirtualAddress + image_base);

		//If the directory has LOCK prefixes table
		//and the loader overwrites our fake LOCK opcode
		//to NOP (0x90) (i.e. the system has a single processor)
		if (cfg->LockPrefixTable && info_copy.lock_opcode == 0x90 /* NOP opcode */)
		{
			//Get pointer to first element of
			//absolute address of LOCK prefixes table
			const DWORD* table_ptr = reinterpret_cast<const DWORD*>(cfg->LockPrefixTable);
			//Enumerate them
			while (true)
			{
				//Pointer to LOCK prefix
				BYTE* lock_prefix_va = reinterpret_cast<BYTE*>(*table_ptr);

				if (!lock_prefix_va)
					break;

				//Change it to NOP
				*lock_prefix_va = 0x90;
			}
		}
	}

	//Pointer to TLS directory
	IMAGE_DATA_DIRECTORY* tls_dir;
	tls_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_TLS);
	//If has TLS
	if(tls_dir->VirtualAddress)
	{
		PIMAGE_TLS_DIRECTORY tls;
		tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(image_base + tls_dir->VirtualAddress);
		//Copy TLS index
		if (tls->AddressOfIndex)
			*reinterpret_cast<DWORD*>(tls->AddressOfIndex) = info_copy.tls_index;  //not a virtual address
		if (tls->AddressOfCallBacks)
		{
			//If TLS has callbacks
			PIMAGE_TLS_CALLBACK* tls_callback_address;
			//Pointer to first callback of an original array
			tls_callback_address = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
			//Offset relative to the beginning of original TLS callbacks array
			DWORD offset = 0;
			while (true)
			{
				//If callback is null - this is the end of array
				if (!*tls_callback_address)
					break;

				//Copy the address of original one
				//to our callbacks array
				*reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.new_rva_of_tls_callbacks + image_base + offset) = *tls_callback_address;

				//Move to next callback
				++tls_callback_address;
				offset += sizeof(DWORD);
			}
			if (offset) // Really have callbacks, Call them like loader
			{
				//Return to the beginning of the new array
				tls_callback_address = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.new_rva_of_tls_callbacks + image_base);
				while(true)
				{
					//If callback is null - this is the end of array
					if(!*tls_callback_address)
						break;

					//Execute callback
					(*tls_callback_address)(reinterpret_cast<PVOID>(image_base), DLL_PROCESS_ATTACH, 0);

					//Move to next callback
					++tls_callback_address;
				}
			}
		}
	}
	
	//Restore headers memory attributes
	virtual_protect(reinterpret_cast<LPVOID>(image_base), rva_of_first_section, old_protect, &old_protect);

	//Free library before leave
	free_library(kernel32_dll);

	//Create epilogue manually
	_asm
	{
		//Move to original entry point
		mov eax, original_ep;
		leave;
		//Like this
		jmp eax;
	}
}