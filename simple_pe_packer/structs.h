#pragma once
#include <Windows.h>

#pragma pack(push, 1)
//Structure to store packed section data
struct packed_section
{
	char name[8]; //Section name
	DWORD virtual_size; //Virtual size
	DWORD virtual_address; //Virtual address (RVA)
	DWORD size_of_raw_data; //Raw data size
	DWORD pointer_to_raw_data; //Raw data file offset
	DWORD characteristics; //Section characteristics
};

//Structure to store information about packed file
struct packed_file_info
{
	DWORD size_of_packed_data; //Size of packed data
	DWORD size_of_unpacked_data; //Size of original data
	
	DWORD lock_opcode; //LOCK assembler command fake opcode

	DWORD tls_index; //Loader writes TLS index here
//	DWORD original_tls_index_rva; //Relative TLS index address in original file
	DWORD new_rva_of_tls_callbacks; //Relative TLS callback array address in file after our modification									
//	DWORD original_rva_of_tls_callbacks; //Original TLS callback array address in original file

	DWORD load_library_a; //LoadLibraryA procedure address from kernel32.dll
	DWORD get_proc_address; //GetProcAddress procedure address from kernel32.dll
	DWORD free_library; //FreeLibrary procedure address from kernel32.dll
	DWORD end_of_import_address_table; //IAT end
};
#pragma pack(pop)
