#include <iostream>
#include <Windows.h>
//File from UniLink distributive
#include "ulnfeat.h"

//Several TLS variables
__declspec(thread) int a = 123;
__declspec(thread) int b = 456;
__declspec(thread) char c[128];

//Couple of TLS callbacks
void __stdcall tls_callback(void*, unsigned long reason, void*)
{
	if(reason == DLL_PROCESS_ATTACH)
		MessageBoxA(0, "1 Process ATTACH Callback !", "Process Callback!",  0);
	else if(reason == DLL_THREAD_ATTACH)
		MessageBoxA(0, "1 Thread ATTACH Callback !", "Thread Callback!",  0);
	else if (reason == DLL_PROCESS_DETACH)
		MessageBoxA(0, "1 Process DETACH Callback !", "Process Callback!",  0);
	else if (reason == DLL_THREAD_DETACH)
		MessageBoxA(0, "1 Thread DETACH Callback !", "Thread Callback!",  0);
}

void __stdcall tls_callback2(void*, unsigned long reason, void*)
{
	if (reason == DLL_PROCESS_ATTACH)
		MessageBoxA(0, "2 Process ATTACH Callback !", "Process Callback!", 0);
	else if (reason == DLL_THREAD_ATTACH)
		MessageBoxA(0, "2 Thread ATTACH Callback !", "Thread Callback!", 0);
	else if (reason == DLL_PROCESS_DETACH)
		MessageBoxA(0, "2 Process DETACH Callback !", "Process Callback!", 0);
	else if (reason == DLL_THREAD_DETACH)
		MessageBoxA(0, "2 Thread DETACH Callback !", "Thread Callback!", 0);
}

//Thread procedure (empty, just to call callbacks)
DWORD __stdcall thread(void*)
{
	ExitThread(0);
}

//Two TLS callbacks
//This declaration is for UniLink linker
TLS_CALLBACK(1, tls_callback);
TLS_CALLBACK(2, tls_callback2);

int main()
{
	//Display variables from TLS
	std::cout << "Relocation test " << a << ", " << b << std::endl;
	c[126] = 'x';
	c[127] = 0;
	std::cout << &c[126] << std::endl;
	
	//Sleep for 2 seconds
	Sleep(2000);
	
	//Start the thread and close its handle right away
	CloseHandle(CreateThread(0, 0, &thread, 0, 0, 0));
	
	//Sleep for 2 seconds
	Sleep(2000);
	return 0;
}
