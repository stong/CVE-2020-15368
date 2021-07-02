struct MyIrpStruct
{
	void* ntoskrnl;
	void (*nt_memcpy)(void* dst, void* src, size_t len);
	void* (*nt_ExAllocatePoolWithTag)(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag);
	NTSTATUS(*nt_PsCreateSystemThread)(PHANDLE ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, void* ClientId, void* StartRoutine, PVOID StartContext);

	void* nt_IofCompleteRequest;
	
	SIZE_T payload_size;
	UCHAR payload[];
};
