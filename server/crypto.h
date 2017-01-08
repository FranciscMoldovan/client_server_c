#pragma once
#include "map.h"

UINT8 key;
MAPPING map;
HANDLE ghMutex;
UINT32 progress;
DWORD dwWaitResult;

void __stdcall xor_with_key(UINT8* aChar, const UINT8 key);
unsigned int __stdcall thread_func(void *data);
void do_work(const char* file_path, const size_t num_threads, const char key);
