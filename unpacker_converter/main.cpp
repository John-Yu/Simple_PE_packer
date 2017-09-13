#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
//PE library header file 
#include "pe_bliss.h"

//Directives to allow linking with built PE library
#ifndef _M_X64
#	ifdef _DEBUG
#		pragma comment(lib, "../pelib/pe_bliss_d.lib")
#	else
#		pragma comment(lib, "../pelib/pe_bliss.lib")
#	endif
#else
#	ifdef _DEBUG
#		pragma comment(lib, "../../pe_bliss_1.0.0/x64/Debug/pe_bliss.lib")
#	else
#		pragma comment(lib, "../../pe_bliss_1.0.0/x64/Release/pe_bliss.lib")
#	endif
#endif

using namespace pe_bliss;

int main(int argc, char* argv[])
{
	//Usage hints
	if(argc != 3)
	{
		std::cout << "Usage: unpacker_converter.exe unpacker.exe output.h" << std::endl;
		return 0;
	}

	//Open unpacker.exe file - its name
	//and path are stored in argv array at index 1
	std::ifstream file(argv[1], std::ios::in | std::ios::binary);
	if(!file)
	{
		//If file open failed - display message and exit with an error
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		std::cout << "Creating unpacker source file..." << std::endl;

		//Try to open the file as 32-bit PE file
		//Last two arguments are false, because we don't need them
		//"raw" file bound import data and
		//"raw" debug information data
		//They are not used while packing, so we don't load these data
		pe_base image(file, pe_properties_32(), false);

		//Get unpacker sections list
		section_list& unpacker_sections = image.get_image_sections();
		//Make sure, that there is only one section (because unpacker doesn't have imports and relocations)
		if(unpacker_sections.size() >2)
		{
			std::cout << "Incorrect unpacker" << std::endl;
			return -1;
		}

		//Get reference to this section data
		std::string& unpacker_section_data = unpacker_sections.at(0).get_raw_data();
		//Remove null bytes at the end of this section, 
		//which were added by compiler for alignment
		pe_utils::strip_nullbytes(unpacker_section_data);

		//Îpen output .h file for writing
		//Its name is stored in argv[2]
		std::ofstream output_source(argv[2], std::ios::out | std::ios::trunc);

		//Start to generate the source code
		output_source << std::hex << "#pragma once" << std::endl << "unsigned char unpacker_data[] = {";
		//Current read data length
		unsigned long len = 0;
		//Total section data length
		std::string::size_type total_len = unpacker_section_data.length();

		//For each byte of data
		for(std::string::const_iterator it = unpacker_section_data.begin(); it != unpacker_section_data.end(); ++it, ++len)
		{
			//Add line endings to
			//provide code readability 
			if((len % 16) == 0)
				output_source << std::endl;

			//Write byte value
			output_source
				<< "0x" << std::setw(2) << std::setfill('0')
				<< static_cast<unsigned long>(static_cast<unsigned char>(*it));

			//And a comma if needed
			if(len != total_len - 1)
				output_source << ", ";
		}

		//End of code
		output_source << " };" << std::endl;
	}
	catch(const pe_exception& e)
	{
		//If by any reason it fails to open
		//Display error message and exit
		std::cout << e.what() << std::endl;
		return -1;
	}

	return 0;
}