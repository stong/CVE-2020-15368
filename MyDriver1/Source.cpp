#include <wdm.h>
#include <ntimage.h>

#include "proto.h"

extern "C"
{
    __int64 __declspec(dllexport) __fastcall MyIRPHandler(struct _DEVICE_OBJECT* a1, IRP* irp)
    {
        ULONG ioctl_no = irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode;
        MyIrpStruct* user_data = (MyIrpStruct*)irp->AssociatedIrp.SystemBuffer;

        void* my_rwx = user_data->nt_ExAllocatePoolWithTag(NonPagedPoolExecute, user_data->payload_size, 'lmao');

        user_data->nt_memcpy(my_rwx, user_data->payload, user_data->payload_size);

        // do relocs
        PIMAGE_DOS_HEADER image = (PIMAGE_DOS_HEADER)my_rwx;
        PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((uintptr_t)my_rwx + image->e_lfanew);
        IMAGE_DATA_DIRECTORY* reloc_dir_info = &pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_BASE_RELOCATION* relocs = (IMAGE_BASE_RELOCATION*)((uintptr_t)my_rwx + reloc_dir_info->VirtualAddress);

        uintptr_t basediff = (uintptr_t)my_rwx - pe->OptionalHeader.ImageBase;

        void* relocs_end = (void*)((uintptr_t)relocs + reloc_dir_info->Size);
        while (relocs < relocs_end)
        {
            ULONG va = relocs->VirtualAddress;
            USHORT* entries = (USHORT*)((uintptr_t)relocs + sizeof(IMAGE_BASE_RELOCATION));
            int num_entries = (relocs->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            for (int i = 0; i < num_entries; i++)
            {
                USHORT entry = entries[i];
                USHORT reloc_type = entry >> 12;
                uintptr_t reloc_offset = (uintptr_t)(entry & 0xfff);
                if (reloc_type == IMAGE_REL_BASED_DIR64)
                {
                    ULONG64* reloc_spot = (ULONG64*)((uintptr_t)my_rwx + va + reloc_offset);
                    *reloc_spot += basediff;
                }
                else if (reloc_type == IMAGE_REL_BASED_ABSOLUTE)
                {
                    // this is padding, skip
                }
                else
                {
                    // this should never happen
                    __debugbreak();
                }
            }
            relocs = (IMAGE_BASE_RELOCATION*)((uintptr_t)relocs + relocs->SizeOfBlock);
        }

        // start thread
        HANDLE hThread;
        void* start_addr = (void*)((uintptr_t)my_rwx + 0x1000);
        user_data->nt_PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)start_addr, NULL);

        ((void (*)(PIRP, CCHAR))user_data->nt_IofCompleteRequest)(irp, 0);

        return 0;
    }

    __int64 __declspec(dllexport) MyIRPHandler_end;

    DRIVER_INITIALIZE DriverEntry;
    _Use_decl_annotations_
        NTSTATUS
        DriverEntry(
            struct _DRIVER_OBJECT* DriverObject,
            PUNICODE_STRING  RegistryPath
        )
    {
#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[rose][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__)

        DBG_LOG("THIS IS FROM MY MANAUAL MAPPED D RIVER!!!!!!!!!!!1\n");
        return STATUS_SUCCESS;
    }
}