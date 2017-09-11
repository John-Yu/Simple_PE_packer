//Include structures file from packer project
#include "../simple_pe_packer/structs.h"

//Unpacking algorithm
#include "lzo_conf.h"
/* decompression */
LZO_EXTERN(int)
lzo1z_decompress        ( const lzo_bytep src, lzo_uint  src_len,
                                lzo_bytep dst, lzo_uintp dst_len,
                                lzo_voidp wrkmem /* NOT USED */ );

//Create function without prologue and epilogue
extern "C" void __declspec(naked) unpacker_main()
{
	//Create prologue manually
	__asm
	{
		jmp next;
		ret 0xC;
next:

		push ebp;
		mov ebp, esp;
		sub esp, 4096;
		
		mov eax, 0x11111111;
		mov ecx, 0x22222222;
		mov edx, 0x33333333;
	}
	
	//Image loading address
	unsigned int original_image_base;
	//First section relative address,
	//in which the packer stores its information
	//and packed data themselves
	unsigned int rva_of_first_section;
	//Image loading address (Original one, relocations are not applied to it)
	unsigned int original_image_base_no_fixup;
	
	//These instructions are required only to
	//replace the addresses in unpacker builder with real ones
	__asm
	{
		mov original_image_base, eax;
		mov rva_of_first_section, ecx;
		mov original_image_base_no_fixup, edx;
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
	info = reinterpret_cast<const packed_file_info*>(original_image_base + rva_of_first_section);

	//Get original entry point address
	DWORD original_ep;
	original_ep = info->original_entry_point + original_image_base;

	__asm
	{
		//Write it to address stored in
		//was_unpacked variable
		mov edx, was_unpacked;
		mov eax, original_ep;
		mov [edx], eax;
	}
	
	//Two LoadLibraryA and GetProcAddress function prototypes typedefs 
	typedef HMODULE (__stdcall* load_library_a_func)(const char* library_name);
	typedef INT_PTR (__stdcall* get_proc_address_func)(HMODULE dll, const char* func_name);

	//Read their addresses from packed_file_info structure
	//Loader puts them there for us
	load_library_a_func load_library_a;
	get_proc_address_func get_proc_address;
	load_library_a = reinterpret_cast<load_library_a_func>(info->load_library_a);
	get_proc_address = reinterpret_cast<get_proc_address_func>(info->get_proc_address);
	
	
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
	lzo1z_decompress(
		reinterpret_cast<const unsigned char*>(reinterpret_cast<DWORD>(info) + sizeof(packed_file_info)),
		info->size_of_packed_data,
		reinterpret_cast<unsigned char*>(unpacked_mem),
		&out_len,
		0);
	
	
	//Pointer to DOS file header
	const IMAGE_DOS_HEADER* dos_header;
	//Pointer to file header
	IMAGE_FILE_HEADER* file_header;
	//Virtual address of sections header beginning
	DWORD offset_to_section_headers;
	//Calculate this address
	dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(original_image_base);
	file_header = reinterpret_cast<IMAGE_FILE_HEADER*>(original_image_base + dos_header->e_lfanew + sizeof(DWORD));
	//with this formula
	offset_to_section_headers = original_image_base + dos_header->e_lfanew + file_header->SizeOfOptionalHeader
		+ sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;
	
	
	//Null first section memory
	//This region matches the memory region,
	//which is occupied by all sections in original file
	memset(
		reinterpret_cast<void*>(original_image_base + rva_of_first_section),
		0,
		info_copy.total_virtual_size_of_sections - rva_of_first_section);

	//Let's change memory block attributes, in which
	//PE file and section headers are placed
	//We need write access
	DWORD old_protect;
	virtual_protect(reinterpret_cast<LPVOID>(offset_to_section_headers),
		info_copy.number_of_sections * sizeof(IMAGE_SECTION_HEADER),
		PAGE_READWRITE, &old_protect);

	//Now we change section number
	//in PE file header to original
	file_header->NumberOfSections = info_copy.number_of_sections;
	
	
	//Section header virtual address
	DWORD current_section_structure_pos;
	current_section_structure_pos = offset_to_section_headers;
	//List all sections
	for(int i = 0; i != info_copy.number_of_sections; ++i)
	{
		//Creates section header structure
		IMAGE_SECTION_HEADER section_header;
		//Set structure to null
		memset(&section_header, 0, sizeof(section_header));
		//Fill the important fields:
		//Characteristics
		section_header.Characteristics = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->characteristics;
		//File data offset
		section_header.PointerToRawData = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->pointer_to_raw_data;
		//File data size
		section_header.SizeOfRawData = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->size_of_raw_data;
		//Relative section virtual address
		section_header.VirtualAddress = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->virtual_address;
		//Section virtual size
		section_header.Misc.VirtualSize = (reinterpret_cast<packed_section*>(unpacked_mem) + i)->virtual_size;
		//Copy original section name
		memcpy(section_header.Name, (reinterpret_cast<packed_section*>(unpacked_mem) + i)->name, sizeof(section_header.Name));

		//Copy filled header
		//to memory, where section headers are stored
		memcpy(reinterpret_cast<void*>(current_section_structure_pos), &section_header, sizeof(section_header));

		//Move the pointer to next section header
		current_section_structure_pos += sizeof(section_header);
	}
	
	
	//Pointer to raw section data
	//is necessary to disassemble compressed sections data
	//and to put them to right places
	DWORD current_raw_data_ptr;
	current_raw_data_ptr = 0;
	//Restore the pointer to section headers
	current_section_structure_pos = offset_to_section_headers;
	//List all the sections again
	for(int i = 0; i != info_copy.number_of_sections; ++i)
	{
		//Section header we've just written
		const IMAGE_SECTION_HEADER* section_header = reinterpret_cast<const IMAGE_SECTION_HEADER*>(current_section_structure_pos);

		//Copying sections data to the place in memory,
		//where they have to be placed
		memcpy(reinterpret_cast<void*>(original_image_base + section_header->VirtualAddress),
			reinterpret_cast<char*>(unpacked_mem) + info_copy.number_of_sections * sizeof(packed_section) + current_raw_data_ptr,
			section_header->SizeOfRawData);

		//Move pointer to section data
		//in unpacked data block
		current_raw_data_ptr += section_header->SizeOfRawData;

		//Turn to next section header
		current_section_structure_pos += sizeof(IMAGE_SECTION_HEADER);
	}
	
	//Release memory with unpacked data,
	//we don't need it anymore
	virtual_free(unpacked_mem, 0, MEM_RELEASE);
	
	
	//Calculate relative virtual address
	//of directory table beginning
	DWORD offset_to_directories;
	offset_to_directories = original_image_base + dos_header->e_lfanew
		+ sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	//Pointer to import directory
	IMAGE_DATA_DIRECTORY* import_dir;
	import_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_IMPORT);
	//Write size and virtual address values to corresponding fields
	import_dir->Size = info_copy.original_import_directory_size;
	import_dir->VirtualAddress = info_copy.original_import_directory_rva;
	
	//Pointer to resource directory
	IMAGE_DATA_DIRECTORY* resource_dir;
	resource_dir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(offset_to_directories + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_RESOURCE);
	//Write size and virtual address values to corresponding fields
	resource_dir->Size = info_copy.original_resource_directory_size;
	resource_dir->VirtualAddress = info_copy.original_resource_directory_rva;

	
	//If the file has imports
	if(info_copy.original_import_directory_rva)
	{
		//First descriptor virtual address
		IMAGE_IMPORT_DESCRIPTOR* descr;
		descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(info_copy.original_import_directory_rva + original_image_base);

		//List all descriptors
		//Last one is nulled
		while(descr->Name)
		{
			//Load the required DLL
			HMODULE dll;
			dll = load_library_a(reinterpret_cast<char*>(descr->Name + original_image_base));
			//Pointers to address table and lookup table
			DWORD* lookup, *address;
			//Take into account that lookup table may be absent,
			//as I mentioned at previous step
			lookup = reinterpret_cast<DWORD*>(original_image_base + (descr->OriginalFirstThunk ? descr->OriginalFirstThunk : descr->FirstThunk));
			address = reinterpret_cast<DWORD*>(descr->FirstThunk + original_image_base);

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
					*address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value + original_image_base + sizeof(WORD))));

				//Move to next element
				++lookup;
				++address;
			}

			//Move to next descriptor
			++descr;
		}
	}

	//If a file had relocations and it
	//was moved by the loader
	if(info_copy.original_relocation_directory_rva
		&& original_image_base_no_fixup != original_image_base)
	{
		//Pointer to a first IMAGE_BASE_RELOCATION structure
		const IMAGE_BASE_RELOCATION* reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(info_copy.original_relocation_directory_rva + original_image_base);

		//Relocated elements (relocations) directory size
		unsigned long reloc_size = info_copy.original_relocation_directory_size;
		//Count of processed bytes in a directory
		unsigned long read_size = 0;

		//List relocation tables
		while(reloc->SizeOfBlock && read_size < reloc_size)
		{
			//List all elements in a table
			for(unsigned long i = sizeof(IMAGE_BASE_RELOCATION); i < reloc->SizeOfBlock; i += sizeof(WORD))
			{
				//Relocation value
				WORD elem = *reinterpret_cast<const WORD*>(reinterpret_cast<const char*>(reloc) + i);
				//If this is IMAGE_REL_BASED_HIGHLOW relocation (there are no other in PE x86)
				if((elem >> 12) == IMAGE_REL_BASED_HIGHLOW)
				{
					//Get DWORD at relocation address
					DWORD* value = reinterpret_cast<DWORD*>(original_image_base + reloc->VirtualAddress + (elem & ((1 << 12) - 1)));
					//Fix it like PE loader
					*value = *value - original_image_base_no_fixup + original_image_base;
				}
			}

			//Calculate number of bytes processed
			//in relocation directory
			read_size += reloc->SizeOfBlock;
			//Go to next relocation table
			reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const char*>(reloc) + reloc->SizeOfBlock);
		}
	}
	
	
	//If file has load configuration directory
	if(info_copy.original_load_config_directory_rva)
	{
		//Get pointer to original load configuration directory
		const IMAGE_LOAD_CONFIG_DIRECTORY32* cfg = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY32*>(info_copy.original_load_config_directory_rva + original_image_base);

		//If the directory has LOCK prefixes table
		//and the loader overwrites our fake LOCK opcode
		//to NOP (0x90) (i.e. the system has a single processor)
		if(cfg->LockPrefixTable && info_copy.lock_opcode == 0x90 /* NOP opcode */)
		{
			//Get pointer to first element of
			//absolute address of LOCK prefixes table
			const DWORD* table_ptr = reinterpret_cast<const DWORD*>(cfg->LockPrefixTable);
			//Enumerate them
			while(true)
			{
				//Pointer to LOCK prefix
				BYTE* lock_prefix_va = reinterpret_cast<BYTE*>(*table_ptr);

				if(!lock_prefix_va)
				break;

				//Change it to NOP
				*lock_prefix_va = 0x90;
			}
		}
	}
	
	//Copy TLS index
	if(info_copy.original_tls_index_rva)
		*reinterpret_cast<DWORD*>(info_copy.original_tls_index_rva + original_image_base) = info_copy.tls_index;
		
	if(info_copy.original_rva_of_tls_callbacks)
	{
		//If TLS has callbacks
		PIMAGE_TLS_CALLBACK* tls_callback_address;
		//Pointer to first callback of an original array
		tls_callback_address = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.original_rva_of_tls_callbacks + original_image_base);
		//Offset relative to the beginning of original TLS callbacks array
		DWORD offset = 0;

		while(true)
		{
			//If callback is null - this is the end of array
			if(!*tls_callback_address)
				break;

			//Copy the address of original one
			//to our callbacks array
			*reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.new_rva_of_tls_callbacks + original_image_base + offset) = *tls_callback_address;

			//Move to next callback
			++tls_callback_address;
			offset += sizeof(DWORD);
		}

		//Return to the beginning of the new array
		tls_callback_address = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(info_copy.new_rva_of_tls_callbacks + original_image_base);
		while(true)
		{
			//If callback is null - this is the end of array
			if(!*tls_callback_address)
				break;

			//Execute callback
			(*tls_callback_address)(reinterpret_cast<PVOID>(original_image_base), DLL_PROCESS_ATTACH, 0);

			//Move to next callback
			++tls_callback_address;
		}
	}
	
	
	//Restore headers memory attributes
	virtual_protect(reinterpret_cast<LPVOID>(offset_to_section_headers), info_copy.number_of_sections * sizeof(IMAGE_SECTION_HEADER), old_protect, &old_protect);

	//Create epilogue manually
	_asm
	{
		//Move to original entry point
		mov eax, info_copy.original_entry_point;
		add eax, original_image_base;
		leave;
		//Like this
		jmp eax;
	}
}