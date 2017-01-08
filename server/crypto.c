#include <Windows.h>
#include <stdio.h>
#include <Windows.h>
#include <process.h>
#include "crypto.h"

void __stdcall xor_with_key(UINT8* aChar, UINT8 key)
{
	*aChar ^= key;
}
unsigned int __stdcall thread_func(void *data)
{
	int *args = (int*)data; 
	for (size_t i = args[0]; i <= args[1]; i++)
	{
		xor_with_key(map.Data + i, (UINT8)args[2]);
	
	
		dwWaitResult = WaitForSingleObject(
			ghMutex, // handle to MUTEX
			INFINITE);

		switch (dwWaitResult)
		{
			// Th got mutex ownership
		case WAIT_OBJECT_0:
			__try {
				progress++;
				// printf("Progress: %.2f %c\r", (float)progress/map.DataSize*100, 37);
				printf("Progress: %.2f %c\n", (float)progress / map.DataSize * 100, 37);
				fflush(stdout);
			}
			__finally {
				// Release mutex ownership
				if (!ReleaseMutex(ghMutex))
				{
					// Handle error
				}
			}
			break;

		default:
			break;
		}
	
	}
}
void do_work(const char* file_path, const size_t num_threads, const UINT8 key)
{
	ghMutex = CreateMutex(
		NULL,              // default security attributes
		FALSE,             // initially not owned
		NULL);             // unnamed mutex

	if (ghMutex == NULL)
	{
		printf("CreateMutex error: %d\n", GetLastError());
		return 1;
	}

	DWORD result;

	result = MapFile(file_path, GENERIC_READ | GENERIC_WRITE, &map);
	if (ERROR_SUCCESS != result)
	{
		printf("MapFile failed with result %u\n", result);
		return result;
	}

	printf("MapFile succeeded\n");
	
	/////// START_FILE_PROCESSING

	int start=0, end=0;
	
	// START_THREADS
	HANDLE* all_threads = (HANDLE*) malloc ( num_threads * sizeof(HANDLE) );
	for (size_t i = 0; i < num_threads; i++)
	{
// Domain decomp
		if (0 == i)
		{
			start = 0;
		}
		else
		{
			start = 1 + i * (map.DataSize - 1) / num_threads;
		}
		end = (i + 1) * (map.DataSize - 1) / num_threads;

		int *th_args = (int*)malloc(3 * sizeof(int));
		th_args[0] = start;
		th_args[1] = end;
		th_args[2] = key;

		printf("TH#%d\n", i);
		printf("[Th%d:START=%d][Th%d:END=%d] diff = %d #elem = %d\n", i, start, i, end, end - start, end - start + 1);
		all_threads[i] = (HANDLE)_beginthreadex(0, 0, &thread_func, th_args, 0, 0);
	}

	WaitForMultipleObjects(num_threads, all_threads, 1, INFINITE);

	for (size_t i = 0; i < num_threads; i++)
	{
		CloseHandle(all_threads[i]);
	}
	// END_THREADS

	UnmapFile(&map);

}