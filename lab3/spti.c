#include <windows.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <strsafe.h>
#include <intsafe.h>
#define _NTSCSI_USER_MODE_
#include <scsi.h>
#include "spti.h"

#define NAME_COUNT  25

#define BOOLEAN_TO_STRING(_b_) \
( (_b_) ? "True" : "False" )

#if defined(_X86_)
    #define PAGE_SIZE  0x1000
    #define PAGE_SHIFT 12L
#elif defined(_AMD64_)
    #define PAGE_SIZE  0x1000
    #define PAGE_SHIFT 12L
#elif defined(_IA64_)
    #define PAGE_SIZE 0x2000
    #define PAGE_SHIFT 13L
#else
    // undefined platform?
    #define PAGE_SIZE  0x1000
    #define PAGE_SHIFT 12L
#endif


LPCSTR BusTypeStrings[] = {
    "Unknown",
    "Scsi",
    "Atapi",
    "Ata",
    "1394",
    "Ssa",
    "Fibre",
    "Usb",
    "RAID",
    "Not Defined",
};
#define NUMBER_OF_BUS_TYPE_STRINGS (sizeof(BusTypeStrings)/sizeof(BusTypeStrings[0]))

VOID __cdecl main(_In_ int argc, _In_z_ char *argv[])
{
    BOOL status = 0;
    DWORD shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE; // default
    DWORD accessMode = GENERIC_WRITE | GENERIC_READ;      // default
    HANDLE fileHandle = NULL;
    ULONG alignmentMask = 0; // default == no alignment requirement
    UCHAR srbType = 0; // default == SRB_TYPE_SCSI_REQUEST_BLOCK
    PUCHAR dataBuffer = NULL;
    PUCHAR pUnAlignedBuffer = NULL;
    SCSI_PASS_THROUGH_WITH_BUFFERS sptwb;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb;
    CHAR PHYSICAL_DRIVE[NAME_COUNT] = "\\\\.\\PHYSICALDRIVE";

    ULONG length = 0,
          errorCode = 0,
          returned = 0,
          sector_cnt = 0,
          LBA_start = 0,
          sectorSize = 512,
          data_pattern = 0;

    

    /* Define drive id.*/
    strncat_s(PHYSICAL_DRIVE, NAME_COUNT, argv[2], _TRUNCATE);

    printf("Path: %s\n", PHYSICAL_DRIVE);

    /*Sector count.*/
    sector_cnt = atoi(argv[7]);

    /*LBA start.*/
    LBA_start = atoi(argv[5]);

    //printf("argc=%d\n", argc);
    dataBuffer = AllocateAlignedBuffer(sectorSize * sector_cnt, alignmentMask, &pUnAlignedBuffer);

    if (argc == 8) // read operation
    {
        if (strcmp("--disk", argv[1]) == 0 && strcmp("--read", argv[3]) == 0 && strcmp("--lba", argv[4]) == 0 && strcmp("--sector_cnt", argv[6]) == 0)
        {
            //printf("read operation\n");
            shareMode = FILE_SHARE_READ;
        }
    }
    else if (argc == 10) // write operation
    {
        //printf("write operation\n");
        shareMode = FILE_SHARE_WRITE;
        data_pattern = strtol(argv[9], NULL, 16);
    }

    fileHandle = CreateFile(PHYSICAL_DRIVE,
       accessMode,
       shareMode,
       NULL,
       OPEN_EXISTING,
       0,
       NULL);

    if (fileHandle == INVALID_HANDLE_VALUE) {
        errorCode = GetLastError();
        printf("Error opening %s. Error: %d\n",
            PHYSICAL_DRIVE, errorCode);
        PrintError(errorCode);
        return;
    }

    //
    // Get the alignment requirements
    //

    status = QueryPropertyForDevice(fileHandle, &alignmentMask, &srbType);
    if (!status ) {
        errorCode = GetLastError();
        printf("Error getting device and/or adapter properties; "
               "error was %d\n", errorCode);
        PrintError(errorCode);
        CloseHandle(fileHandle);
        return;
    }

    //ZeroMemory(dataBuffer,sectorSize);

    if (argc == 8) // read operation
    {
        //printf("            *****       READ DATA BUFFER operation         *****\n");

        ZeroMemory(dataBuffer, sectorSize * sector_cnt);
        ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
        sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sptdwb.sptd.PathId = 0;
        sptdwb.sptd.TargetId = 1;
        sptdwb.sptd.Lun = 0;
        sptdwb.sptd.CdbLength = 16;
        sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_IN;
        sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
        sptdwb.sptd.DataTransferLength = sectorSize * sector_cnt;
        sptdwb.sptd.TimeOutValue = 2;
        sptdwb.sptd.DataBuffer = dataBuffer;
        sptdwb.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER,ucSenseBuf);

        UINT64 LBA_read = LBA_start;
        sptdwb.sptd.Cdb[0] = (UCHAR)0x88;
        sptdwb.sptd.Cdb[2] = (UCHAR)(LBA_read >> 56);
        sptdwb.sptd.Cdb[3] = (UCHAR)(LBA_read >> 48);
        sptdwb.sptd.Cdb[4] = (UCHAR)(LBA_read >> 40);
        sptdwb.sptd.Cdb[5] = (UCHAR)(LBA_read >> 32);
        sptdwb.sptd.Cdb[6] = (UCHAR)(LBA_read >> 24);
        sptdwb.sptd.Cdb[7] = (UCHAR)(LBA_read >> 16);
        sptdwb.sptd.Cdb[8] = (UCHAR)(LBA_read >> 8);
        sptdwb.sptd.Cdb[9] = (UCHAR)(LBA_read);

        sptdwb.sptd.Cdb[10] = (UCHAR)(sector_cnt >> 24);
        sptdwb.sptd.Cdb[11] = (UCHAR)(sector_cnt >> 16);
        sptdwb.sptd.Cdb[12] = (UCHAR)(sector_cnt >> 8);
        sptdwb.sptd.Cdb[13] = (UCHAR)(sector_cnt);

        length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                 &sptdwb,
                                 length,
                                 &sptdwb,
                                 length,
                                 &returned,
                                 FALSE);
        
 /*       PrintStatusResults(status,returned,
           (PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb,length);*/

        if ((sptdwb.sptd.ScsiStatus == 0) && (status != 0)) {
           PrintDataBuffer(dataBuffer,sptdwb.sptd.DataTransferLength);
        }
    }

    
    
    //dataBuffer = AllocateAlignedBuffer(sectorSize * sector_cnt, alignmentMask, &pUnAlignedBuffer);
    //FillMemory(dataBuffer,sectorSize/2,'N');
    //FillMemory(dataBuffer + sectorSize/2,sectorSize/2,'T');

    else if (argc == 10) // write operation
    {
        //printf("            *****       WRITE DATA BUFFER operation         *****\n");
        
        // Set buffer size and data pattern.
        FillMemory(dataBuffer, sectorSize* sector_cnt, data_pattern);

        ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));

        sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sptdwb.sptd.PathId = 0;
        sptdwb.sptd.TargetId = 1;
        sptdwb.sptd.Lun = 0;
        sptdwb.sptd.CdbLength = 16;
        sptdwb.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
        sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
        sptdwb.sptd.DataTransferLength = sectorSize * sector_cnt;
        sptdwb.sptd.TimeOutValue = 2;
        sptdwb.sptd.DataBuffer = dataBuffer;
        sptdwb.sptd.SenseInfoOffset =
           offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER,ucSenseBuf);

        UINT64 LBA_write = LBA_start;
        sptdwb.sptd.Cdb[0] = (UCHAR)(0x8A);
        sptdwb.sptd.Cdb[1] = (UCHAR)0; // Data mode
        sptdwb.sptd.Cdb[2] = (UCHAR)(LBA_write >> 56);
        sptdwb.sptd.Cdb[3] = (UCHAR)(LBA_write >> 48);
        sptdwb.sptd.Cdb[4] = (UCHAR)(LBA_write >> 40);
        sptdwb.sptd.Cdb[5] = (UCHAR)(LBA_write >> 32);
        sptdwb.sptd.Cdb[6] = (UCHAR)(LBA_write >> 24);
        sptdwb.sptd.Cdb[7] = (UCHAR)(LBA_write >> 16);
        sptdwb.sptd.Cdb[8] = (UCHAR)(LBA_write >> 8);
        sptdwb.sptd.Cdb[9] = (UCHAR)(LBA_write);

        sptdwb.sptd.Cdb[10] = (UCHAR)(sector_cnt >> 24);
        sptdwb.sptd.Cdb[11] = (UCHAR)(sector_cnt >> 16);
        sptdwb.sptd.Cdb[12] = (UCHAR)(sector_cnt >> 8);
        sptdwb.sptd.Cdb[13] = (UCHAR)(sector_cnt);

        length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

        status = DeviceIoControl(fileHandle,
                                 IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                 &sptdwb,
                                 length,
                                 &sptdwb,
                                 length,
                                 &returned,
                                 FALSE);
        if (status == 0)
            printf("Write failed, please turn off write protection\n");
        else if (status == 1)
            printf("Write Success\n");
        
        //PrintStatusResults(status,returned,
        //   (PSCSI_PASS_THROUGH_WITH_BUFFERS)&sptdwb,length);

        //if ((sptdwb.sptd.ScsiStatus == 0) && (status != 0)) {
        //   PrintDataBuffer(dataBuffer,sptdwb.sptd.DataTransferLength);
        //}
        // printf("FINISHED\n");
    }

    if (pUnAlignedBuffer != NULL) {
        free(pUnAlignedBuffer);
    }
    CloseHandle(fileHandle);
}

VOID
PrintError(ULONG ErrorCode)
{
    CHAR errorBuffer[80];
    ULONG count;

    count = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL,
                  ErrorCode,
                  0,
                  errorBuffer,
                  sizeof(errorBuffer),
                  NULL
                  );

    if (count != 0) {
        printf("%s\n", errorBuffer);
    } else {
        printf("Format message failed.  Error: %d\n", GetLastError());
    }
}

VOID
PrintDataBuffer(_In_reads_(BufferLength) PUCHAR DataBuffer, _In_ ULONG BufferLength)
{
    ULONG Cnt;

    printf("      00  01  02  03  04  05  06  07   08  09  0A  0B  0C  0D  0E  0F\n");
    printf("      ---------------------------------------------------------------\n");
    for (Cnt = 0; Cnt < BufferLength; Cnt++) {
       if ((Cnt) % 16 == 0) {
          printf(" %03X  ",Cnt);
          }
       printf("%02X  ", DataBuffer[Cnt]);
       if ((Cnt+1) % 8 == 0) {
          printf(" ");
          }
       if ((Cnt+1) % 16 == 0) {
          printf("\n");
          }
       }
    printf("\n\n");
}

_Success_(return != NULL)
_Post_writable_byte_size_(size)
PUCHAR
AllocateAlignedBuffer(
    _In_ ULONG size,
    _In_ ULONG AlignmentMask,
    _Outptr_result_maybenull_ PUCHAR *pUnAlignedBuffer)
{
    PUCHAR ptr;

    // NOTE: This routine does not allow for a way to free
    //       memory.  This is an excercise left for the reader.
    UINT_PTR    align64 = (UINT_PTR)AlignmentMask;

    if (AlignmentMask == 0) {
       ptr = malloc(size);
       *pUnAlignedBuffer = ptr;
    } else {
       ULONG totalSize;

       (void) ULongAdd(size, AlignmentMask, &totalSize);
       ptr = malloc(totalSize);
       *pUnAlignedBuffer = ptr;
       ptr = (PUCHAR)(((UINT_PTR)ptr + align64) & ~align64);
    }

    if (ptr == NULL) {
       printf("Memory allocation error.  Terminating program\n");
       exit(1);
    } else {
       return ptr;
    }
}

VOID
PrintStatusResults(
    BOOL status,DWORD returned,PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb,
    ULONG length)
{
    ULONG errorCode;

    if (!status ) {
       printf( "Error: %d  ",
          errorCode = GetLastError() );
       PrintError(errorCode);
       return;
       }
    if (psptwb->spt.ScsiStatus) {
       PrintSenseInfo(psptwb);
       return;
       }
    else {
       printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
          psptwb->spt.ScsiStatus,returned);
       printf("Data buffer length: %Xh\n\n\n",
          psptwb->spt.DataTransferLength);
       PrintDataBuffer((PUCHAR)psptwb,length);
       }
}

VOID
PrintSenseInfo(PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb)
{
    UCHAR i;

    printf("Scsi status: %02Xh\n\n",psptwb->spt.ScsiStatus);
    if (psptwb->spt.SenseInfoLength == 0) {
       return;
       }
    printf("Sense Info -- consult SCSI spec for details\n");
    printf("-------------------------------------------------------------\n");
    for (i=0; i < psptwb->spt.SenseInfoLength; i++) {
       printf("%02X ",psptwb->ucSenseBuf[i]);
       }
    printf("\n\n");
}


_Success_(return)
BOOL
QueryPropertyForDevice(
    _In_ IN HANDLE DeviceHandle,
    _Out_ OUT PULONG AlignmentMask,
    _Out_ OUT PUCHAR SrbType
    )
{
    PSTORAGE_ADAPTER_DESCRIPTOR adapterDescriptor = NULL;
    PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor = NULL;
    STORAGE_DESCRIPTOR_HEADER header = {0};

    BOOL ok = TRUE;
    BOOL failed = TRUE;
    ULONG i;

    *AlignmentMask = 0; // default to no alignment
    *SrbType = 0; // default to SCSI_REQUEST_BLOCK

    // Loop twice:
    //  First, get size required for storage adapter descriptor
    //  Second, allocate and retrieve storage adapter descriptor
    //  Third, get size required for storage device descriptor
    //  Fourth, allocate and retrieve storage device descriptor
    for (i=0;i<4;i++) {

        PVOID buffer = NULL;
        ULONG bufferSize = 0;
        ULONG returnedData;

        STORAGE_PROPERTY_QUERY query = {0};

        switch(i) {
            case 0: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageAdapterProperty;
                bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
                buffer = &header;
                break;
            }
            case 1: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageAdapterProperty;
                bufferSize = header.Size;
                if (bufferSize != 0) {
                    adapterDescriptor = LocalAlloc(LPTR, bufferSize);
                    if (adapterDescriptor == NULL) {
                        goto Cleanup;
                    }
                }
                buffer = adapterDescriptor;
                break;
            }
            case 2: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageDeviceProperty;
                bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
                buffer = &header;
                break;
            }
            case 3: {
                query.QueryType = PropertyStandardQuery;
                query.PropertyId = StorageDeviceProperty;
                bufferSize = header.Size;

                if (bufferSize != 0) {
                    deviceDescriptor = LocalAlloc(LPTR, bufferSize);
                    if (deviceDescriptor == NULL) {
                        goto Cleanup;
                    }
                }
                buffer = deviceDescriptor;
                break;
            }
        }

        // buffer can be NULL if the property queried DNE.
        if (buffer != NULL) {
            RtlZeroMemory(buffer, bufferSize);

            // all setup, do the ioctl
            ok = DeviceIoControl(DeviceHandle,
                                 IOCTL_STORAGE_QUERY_PROPERTY,
                                 &query,
                                 sizeof(STORAGE_PROPERTY_QUERY),
                                 buffer,
                                 bufferSize,
                                 &returnedData,
                                 FALSE);
            if (!ok) {
                if (GetLastError() == ERROR_MORE_DATA) {
                    // this is ok, we'll ignore it here
                } else if (GetLastError() == ERROR_INVALID_FUNCTION) {
                    // this is also ok, the property DNE
                } else if (GetLastError() == ERROR_NOT_SUPPORTED) {
                    // this is also ok, the property DNE
                } else {
                    // some unexpected error -- exit out
                    goto Cleanup;
                }
                // zero it out, just in case it was partially filled in.
                RtlZeroMemory(buffer, bufferSize);
            }
        }
    } // end i loop



    failed = FALSE;

Cleanup:
    if (adapterDescriptor != NULL) {
        LocalFree( adapterDescriptor );
    }
    if (deviceDescriptor != NULL) {
        LocalFree( deviceDescriptor );
    }
    return (!failed);

}

