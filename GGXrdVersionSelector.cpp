#include "framework.h"
#include "GGXrdVersionSelector.h"
#include "Version.h"  // I included this file so that when it changes, it triggers the Pre-Build event and updates versions in the .rc file
#include <vector>
#include <string>
#include <Psapi.h>
#include "WError.h"
#include <algorithm>
#include <CommCtrl.h>
#include <sstream>
#include "Sig.h"
// from https://learn.microsoft.com/en-us/windows/win32/controls/cookbook-overview
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];                  // Main window's title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // The main window class name
HFONT font = NULL;
HWND mainWindow = NULL;
HBRUSH hbrBkgnd = NULL;
std::vector<HWND> ggNotFoundTextHwnd;
DWORD GetVersionForBattlePlace = 0;
DWORD isVer1_10OrHigherPlace = 0;
DWORD staticTextHeight = 0;
HWND comboBoxHwnd = NULL;
int prevComboBoxSel = -1;

ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

DWORD findOpenGgProcess(DWORD* threadId = nullptr);
void tryFindGg();
void whenGGFound(DWORD procId);
void updateStaticText(const wchar_t* txt);
const char* sigscan(const char* start, const char* end, const char* sig, const char* mask);
const char* sigscan(const char* start, const char* end, const char* sig, size_t sigLength);
template<size_t size>
inline const char* sigscan(const char* start, const char* end, const char (&sig)[size]) {
	return sigscan(start, end, sig, size - 1);
}
const char* sigscan(const char* start, const char* end, const Sig& sig) {
	return sigscan(start, end, sig.sig.data(), sig.mask.data());
}
bool findSectionBounds(const char* name, BYTE* moduleBase, BYTE** start, BYTE** end);
void logError(const char* fmt, ...);
bool findPlaces(HANDLE proc, MODULEINFO* info);
void onComboSelChanged();
bool openGGProcAndGetModuleInfo(DWORD procId, HANDLE* procPtr, MODULEINFO* info);

enum ComboBoxSelection {
	CBSEL_LATEST,  // 0
	CBSEL_25A,  // 1
	CBSEL_25,  // 2
	CBSEL_REV1_LATEST,  // 3
	CBSEL_20A,  // 4
	CBSEL_20,  // 5
	CBSEL_20PRE1_10  // 6
};

char ExeName[] = "\x92\x8f\xae\x51\xea\x8a\x0f\x5f\x23\x70\x44\xb7\x63\xd2\x55\x61\x6a\x00";  // GuiltyGearXrd.exe
ULONGLONG ExeKey = 0x411700002fbcULL;
wchar_t exe[sizeof ExeName];  // single-byte string will get inflated to wide-char

char kernel32Name[] = "\x74\xe5\xa0\x26\x30\xac\x03\xa9\x31\x0c\x94\x12\x62";  // KERNEL32.DLL
ULONGLONG kernel32Key = 0x7c7b00001768ULL;
HMODULE kernel32 = NULL;

char user32Name[] = "\xd8\xac\x44\x11\xc8\xb2\x8a\xb8\x90\x0c\xa1";  // USER32.DLL
ULONGLONG user32Key = 0x562200006c2cULL;
HMODULE user32 = NULL;

char PsapiName[] = "\x94\x99\x87\x60\x59\x1e\x62\x2b\x28\x09";  // PSAPI.DLL
ULONGLONG PsapiKey = 0x4e8600006cccULL;
HMODULE Psapi = NULL;

char OpenProcessName[] = "\xe3\xd2\x1a\xd1\x06\xd3\x1f\xce\xf2\x85\x53\x03";  // OpenProcess
ULONGLONG OpenProcessKey = 0x4d7d00003d60ULL;
HANDLE (__stdcall*OpenProcessPtr)(DWORD, BOOL, DWORD) = nullptr;

char OpenThreadName[] = "\xaa\x0a\x82\xb5\x0b\x95\x65\xe0\x94\xe9\x24";  // OpenThread
ULONGLONG OpenThreadKey = 0x5e1000007e5aULL;
HANDLE (__stdcall*OpenThreadPtr)(DWORD, BOOL, DWORD) = nullptr;

#if defined( _WIN64 )
char Wow64SuspendThreadName[] = "\xda\x9f\x64\x1e\xcd\x0c\x88\xf6\xf0\x14\xfc\x2b\x24\xd5\xd5\xc5\x18\x10\x7a";  // Wow64SuspendThread
ULONGLONG Wow64SuspendThreadKey = 0x37d500006c6aULL;
DWORD (__stdcall*Wow64SuspendThreadPtr)(HANDLE) = nullptr;

char Wow64GetThreadContextName[] = "\x3f\x9f\x78\x16\x61\x0d\xe3\xb0\x2b\x10\x5c\xdf\x1a\x98\x84\x6e\xaa\xa4\x0e\x3e\x6f\x70";  // Wow64GetThreadContext
ULONGLONG Wow64GetThreadContextKey = 0x3cef00001c38ULL;
DWORD (__stdcall*Wow64GetThreadContextPtr)(HANDLE, PWOW64_CONTEXT) = nullptr;
#else
char SuspendThreadName[] = "\xb5\x20\x6c\x8a\xae\xdb\x5a\x20\x61\xa6\x3f\x1a\x98\x80";  // SuspendThread
ULONGLONG SuspendThreadKey = 0x117b0000509dULL;
DWORD (__stdcall*SuspendThreadPtr)(HANDLE) = nullptr;

char GetThreadContextName[] = "\x29\xa2\xe9\x59\x0a\x27\x89\x27\x34\x33\xbd\x4e\x72\xec\x10\x93\xa1";  // GetThreadContext
ULONGLONG GetThreadContextKey = 0x3cf900005b52ULL;
DWORD (__stdcall*GetThreadContextPtr)(HANDLE, LPCONTEXT) = nullptr;
#endif

char ResumeThreadName[] = "\xf0\x8e\xb4\xcb\x1a\x18\xa3\xaa\xad\x60\x55\x38\x24";  // ResumeThread
ULONGLONG ResumeThreadKey = 0x397b00000691ULL;
DWORD (__stdcall*ResumeThreadPtr)(HANDLE) = nullptr;

char CreateRemoteThreadName[] = "\x4e\xe1\x40\x98\x8b\x9a\x6e\x9b\xea\xf5\x0d\x70\x50\x93\x6d\x8a\x92\x1a\x10";  // CreateRemoteThread
ULONGLONG CreateRemoteThreadKey = 0x4de200000663ULL;
HANDLE (__stdcall*CreateRemoteThreadPtr)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = nullptr;

char VirtualAllocExName[] = "\x28\x49\x78\x5b\x33\xd0\x8d\x72\xaa\x6d\x9f\xe6\x0a\x28\x44";  // VirtualAllocEx
ULONGLONG VirtualAllocExKey = 0x7c7d00002b16ULL;
LPVOID (__stdcall*VirtualAllocExPtr)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = nullptr;

char ReadProcessMemoryName[] = "\x88\xe2\x22\x7a\x29\x66\x97\xe7\x62\x7a\x25\x4d\x99\x12\xbe\x91\x7f\xb0";  // ReadProcessMemory
ULONGLONG ReadProcessMemoryKey = 0x4e3100003d2fULL;
BOOL (__stdcall*ReadProcessMemoryPtr)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = nullptr;

char WriteProcessMemoryName[] = "\x38\x82\x7a\xea\x78\x03\xfd\xdc\x6c\x8f\xb0\xe2\x97\x92\xae\x67\xb7\x88\x33";  // WriteProcessMemory
ULONGLONG WriteProcessMemoryKey = 0x23200000acdULL;
BOOL (__stdcall*WriteProcessMemoryPtr)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = nullptr;

char VirtualFreeExName[] = "\x96\x14\x4c\x79\x7a\xd1\x32\xc6\x03\xb8\xbb\x1a\x7c\x00";  // VirtualFreeEx
ULONGLONG VirtualFreeExKey = 0x24c0000029a5ULL;
BOOL (__stdcall*VirtualFreeExPtr)(HANDLE, LPVOID, SIZE_T, DWORD) = nullptr;

char VirtualProtectExName[] = "\xbe\x14\xb4\xf3\xa1\x14\x60\x48\x87\xd7\x8f\x33\xc4\xb8\x38\x06\x3b";  // VirtualProtectEx
ULONGLONG VirtualProtectExKey = 0x280700001d4eULL;
BOOL (__stdcall*VirtualProtectExPtr)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) = nullptr;

char EnumProcessModulesExName[] = "\x21\x6c\xea\x5a\x30\xb1\xeb\xb2\xeb\x95\x6a\xed\x66\x5d\x0b\xe2\x59\x3d\x2d\x75\x01";  // EnumProcessModulesEx
ULONGLONG EnumProcessModulesExKey = 0x14060000408fULL;
BOOL (__stdcall*EnumProcessModulesExPtr)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD) = nullptr;

char GetModuleBaseNameWName[] = "\xa3\x56\x89\x1f\x9e\xd5\x30\xac\x63\xee\x1b\x15\xb9\x29\x30\xe3\xc2\xb5\x01";  // GetModuleBaseNameW
ULONGLONG GetModuleBaseNameWKey = 0x4589000012ecULL;
DWORD (__stdcall*GetModuleBaseNameWPtr)(HANDLE, HMODULE, LPWSTR, DWORD) = nullptr;

char GetModuleFileNameExWName[] = "\x96\x9a\xa1\x8e\xbf\x86\x05\x93\xea\xcc\x30\xe7\xc4\x4b\xe6\xf2\x3a\x89\x0d\x87\x84";  // GetModuleFileNameExW
ULONGLONG GetModuleFileNameExWKey = 0x326b0000027dULL;
DWORD (__stdcall*GetModuleFileNameExWPtr)(HANDLE, HMODULE, LPWSTR, DWORD) = nullptr;

char GetModuleInformationName[] = "\xac\x65\xb9\x62\x6c\x62\xad\xf2\x9b\xba\x94\xad\x1f\x49\x86\xa3\x5c\x57\xa7\x93\x94";  // GetModuleInformation
ULONGLONG GetModuleInformationKey = 0x60a000073a5ULL;
BOOL (__stdcall*GetModuleInformationPtr)(HANDLE, HMODULE, LPMODULEINFO, DWORD) = nullptr;

char CloseHandleName[] = "\xa4\x61\xb7\xa6\x17\x60\xaf\x10\xa6\xb3\x92\x84";  // CloseHandle
ULONGLONG CloseHandleKey = 0x6a560000698dULL;
BOOL (__stdcall*CloseHandlePtr)(HANDLE) = nullptr;

char LoadLibraryWName[] = "\x54\x24\x82\xf3\xc8\x9c\x4f\xb4\xe5\xa2\xc9\xe3\x00";  // LoadLibrary
ULONGLONG LoadLibraryWKey = 0x43fa00005955ULL;
HMODULE (__stdcall*LoadLibraryWPtr)(LPCWSTR) = nullptr;

char FreeLibraryName[] = "\x88\x40\x16\x47\xa3\x9e\x15\x48\x96\x4d\x7c\x95";  // FreeLibrary
ULONGLONG FreeLibraryKey = 0x3fdc00003157ULL;
BOOL (__stdcall*FreeLibraryPtr)(HMODULE) = nullptr;

char FindWindowWName[] = "\x06\x68\x97\x7b\xc6\x1c\x17\x38\x77\x7f\x27\x03";  // FindWindowW
ULONGLONG FindWindowWKey = 0x4abb00006e71ULL;
HWND (__stdcall*FindWindowWPtr)(LPCWSTR, LPCWSTR) = nullptr;

char GetWindowThreadProcessIdName[] = "\x06\x50\xb6\xef\xb8\x4d\xf8\xf9\x1a\x88\xde\x99\x06\x17\xc4\x85\xcc\xa5\xbc\xc2\x9e\x0c\x37\x2b\x2a";  // GetWindowThreadProcessId
ULONGLONG GetWindowThreadProcessIdKey = 0x2bd500006949ULL;
DWORD (__stdcall*GetWindowThreadProcessIdPtr)(HWND, LPDWORD) = nullptr;

// this is for your use at home
unsigned long long generateNewKey() {
	static bool sranded = false;
	if (!sranded) {
		sranded = true;
		srand(GetTickCount64() % 0xFFFFFFFFULL);
	}
	return ((unsigned long long)rand() << 32) | (unsigned long long)rand();
}

// if you know what algorithm this is, let me know
void scramble(std::vector<char>& vec, unsigned long long key) {
	int totalBits = (int)(vec.size() & 0xFFFFFFFF) * (int)8;
	DWORD hash = key & 0xFFFFFFFF;
	
	std::vector<int> unshiftedBits;
	unshiftedBits.reserve(totalBits);
	for (int bitIndex = 0; bitIndex < totalBits; ++bitIndex) {
		unshiftedBits.push_back(bitIndex);
	}
	
	while (unshiftedBits.size() >= 2) {
		key = _rotl64(key, hash % 65);
		hash = hash * 0x89 + key % 0xFFFFFFFF;
		DWORD unsiftedBitsSizeCast = (DWORD)(unshiftedBits.size() & 0xFFFFFFFF);
		int keyStartPos = hash % 8;
		BYTE keyByte = ((BYTE*)&key)[keyStartPos];
		int offset1 = keyByte & 0xf;
		int offset2 = (keyByte >> 4) & 0xf;
		
		int pos1Mapped = (hash + offset1) % unsiftedBitsSizeCast;
		int pos2Mapped = (hash + offset2) % unsiftedBitsSizeCast;
		if (pos1Mapped == pos2Mapped) {
			if (pos1Mapped == unsiftedBitsSizeCast - 1) {
				pos1Mapped = 0;
			} else {
				++pos1Mapped;
			}
		}
		
		int pos1Vec = unshiftedBits[pos1Mapped];
		int pos2Vec = unshiftedBits[pos2Mapped];
		
		if (pos2Mapped < pos1Mapped) {
			int temp = pos1Mapped;
			pos1Mapped = pos2Mapped;
			pos2Mapped = temp;
		}
		unshiftedBits.erase(unshiftedBits.begin() + pos2Mapped);
		unshiftedBits.erase(unshiftedBits.begin() + pos1Mapped);
		
		BYTE pos1VecInd = pos1Vec >> 3;
		BYTE pos2VecInd = pos2Vec >> 3;
		BYTE pos1Byte = vec[pos1VecInd];
		BYTE pos2Byte = vec[pos2VecInd];
		BYTE pos1BitIndex = pos1Vec & 7;
		BYTE pos2BitIndex = pos2Vec & 7;
		BYTE pos1BitMask = 1 << pos1BitIndex;
		BYTE pos2BitMask = 1 << pos2BitIndex;
		BYTE pos1BitValue = (pos1Byte & pos1BitMask) >> pos1BitIndex;
		BYTE pos2BitValue = (pos2Byte & pos2BitMask) >> pos2BitIndex;
		
		if (pos1BitValue == pos2BitValue) {
			continue;
		}
		
		if (pos1VecInd == pos2VecInd) {
			
			BYTE posVecInd = pos1VecInd;
			BYTE posByte = pos1Byte;
			
			if (pos2BitValue) {
				posByte |= pos1BitMask;
			} else {
				posByte &= ~pos1BitMask;
			}
			
			if (pos1BitValue) {
				posByte |= pos2BitMask;
			} else {
				posByte &= ~pos2BitMask;
			}
			
			vec[posVecInd] = posByte;
			
		} else {
			
			if (pos2BitValue) {
				pos1Byte |= pos1BitMask;
			} else {
				pos1Byte &= ~pos1BitMask;
			}
			
			if (pos1BitValue) {
				pos2Byte |= pos2BitMask;
			} else {
				pos2Byte &= ~pos2BitMask;
			}
			
			vec[pos1VecInd] = pos1Byte;
			vec[pos2VecInd] = pos2Byte;
			
		}
		
	}
}

template<size_t size>
inline const char* unscramble(std::vector<char>& vec, const char(&txt)[size], ULONGLONG key) {
	vec.resize(size - 1);
	memcpy(vec.data(), txt, size - 1);
	scramble(vec, key);
	return vec.data();
}

// this is for your use at home
void printByteVec(const std::vector<char>& vec) {
	printf("\"");
	bool isFirst = false;
	for (char c : vec) {
		printf("\\x%.2hhx", c);
	}
	printf("\"\n");
}

// this is for your use at home
void printText(const std::vector<char>& vec) {
	printf("\"");
	for (char c : vec) {
		if (c >= 'a' && c <= 'z'
				|| c >= 'A' && c <= 'Z'
				|| c == '.'
				|| c >= '0' && c <= '9') {
			printf("%c", c);
		} else {
			printf("\\x%.2hhx", c);
		}
	}
	printf("\"\n");
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_GGXRDVERSIONSELECTOR, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);
	SIG_LOG_ERROR_FUNC = logError;

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(IDC_GGXRDVERSIONSELECTOR));

    MSG msg;

    // Main message loop:
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        if (!TranslateAcceleratorW(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_GGXRDVERSIONSELECTOR));
    wcex.hCursor        = LoadCursorW(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_GGXRDVERSIONSELECTOR);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIconW(wcex.hInstance, MAKEINTRESOURCEW(IDI_GGXRDVERSIONSELECTOR));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance; // Store instance handle in our global variable
	
	mainWindow = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
	CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);
	
	if (!mainWindow)
	{
		return FALSE;
	}
	
	NONCLIENTMETRICSW nonClientMetrics { 0 };
	nonClientMetrics.cbSize = sizeof(NONCLIENTMETRICSW);
	SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &nonClientMetrics, NULL);
	font = CreateFontIndirectW(&nonClientMetrics.lfCaptionFont);
	
	hbrBkgnd = GetSysColorBrush(COLOR_WINDOW);
	
	ShowWindow(mainWindow, nCmdShow);
	UpdateWindow(mainWindow);
	
	SetTimer(mainWindow, 1, 1000, NULL);
	
	return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
	case WM_CTLCOLORSTATIC: {
		// Provides background and text colors for static (text) controls.
		if (std::find(ggNotFoundTextHwnd.begin(), ggNotFoundTextHwnd.end(), (HWND)lParam) != ggNotFoundTextHwnd.end()) {
			return (INT_PTR)hbrBkgnd;
		}
		return DefWindowProcW(hWnd, message, wParam, lParam);
	}
	break;
	case WM_TIMER:
		{
			if (wParam == 1)
			{
				tryFindGg();
			}
		}
		break;
    case WM_COMMAND:
        {
        	int controlDefinedNotificationCode = HIWORD(wParam);
        	if (controlDefinedNotificationCode == CBN_SELCHANGE && (HWND)lParam == comboBoxHwnd && comboBoxHwnd) {
        		onComboSelChanged();
        		break;
        	}
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProcW(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Finds if GuiltyGearXrd.exe is currently open and returns the ID of its process
DWORD findOpenGgProcess(DWORD* threadId) {
	std::vector<char> vec;
	if (!user32) {
		user32 = LoadLibraryA(unscramble(vec, user32Name, user32Key));
	}
	
    // this method was chosen because it's much faster than enumerating all windows or all processes and checking their names
    // also it was chosen because Xrd restarts itself upon launch, and the window appears only on the second, true start
    FindWindowWPtr = (HWND(__stdcall*)(LPCWSTR,LPCWSTR))GetProcAddress(user32, unscramble(vec, FindWindowWName, FindWindowWKey));
    HWND foundGgWindow = (*FindWindowWPtr)(L"LaunchUnrealUWindowsClient", L"Guilty Gear Xrd -REVELATOR-");
    if (!foundGgWindow) return NULL;
    DWORD windsProcId = 0;
    GetWindowThreadProcessIdPtr = (DWORD(__stdcall*)(HWND, LPDWORD))
    		GetProcAddress(user32, unscramble(vec, GetWindowThreadProcessIdName, GetWindowThreadProcessIdKey));
    DWORD resultThreadId = (*GetWindowThreadProcessIdPtr)(foundGgWindow, &windsProcId);
    if (threadId) *threadId = resultThreadId;
    return windsProcId;
}

void tryFindGg() {
	DWORD procId = findOpenGgProcess();
	if (!procId) {
		updateStaticText(L"Waiting for GuiltyGearXrd.exe process to open (Please launch the game)");
	} else {
		KillTimer(mainWindow, 1);
		whenGGFound(procId);
	}
}

bool findSectionBounds(const char* name, BYTE* moduleBase, BYTE** start, BYTE** end) {
	BYTE* peHeaderStart = moduleBase + *(DWORD*)(moduleBase + 0x3C);
	unsigned short numberOfSections = *(unsigned short*)(peHeaderStart + 0x6);
	unsigned short optionalHeaderSize = *(unsigned short*)(peHeaderStart + 0x14);
	BYTE* optionalHeaderStart = peHeaderStart + 0x18;
	BYTE* sectionStart = optionalHeaderStart + optionalHeaderSize;
	for (; numberOfSections != 0; --numberOfSections) {
		if (strncmp((const char*)(sectionStart), name, 8) == 0) {
			*start = moduleBase + *(unsigned int*)(sectionStart + 12);
			*end = moduleBase + *(unsigned int*)(sectionStart + 8);
			return true;
		}
		sectionStart += 40;
	}
	return false;
}

void whenGGFound(DWORD procId) {
	
	struct Cleanup {
		HANDLE proc = NULL;
		~Cleanup() {
			if (proc) {
				(*CloseHandlePtr)(proc);
			}
		}
	} cleanup;
	
	MODULEINFO info;
	if (!openGGProcAndGetModuleInfo(procId, &cleanup.proc, &info)) return;
	if (!findPlaces(cleanup.proc, &info)) return;
	
	WPARAM curSel = (UINT_PTR)-1;
	BYTE buf[10];
	SIZE_T bytesRead;
	if (!ReadProcessMemoryPtr(cleanup.proc, (LPCVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace), buf, 10, &bytesRead)) {
		logError("Failed to read GetVersionForBattle code at offset 0x%.8x", GetVersionForBattlePlace);
		return;
	}
	
	if (buf[0] == 0xe8) {  // a CALL instruction
		curSel = 0;
	} else if (memcmp(buf, "\x90\x90\x90\x90\x90", 5) == 0  // NOPs
			&& buf[5] == 0xbe) {  // MOV ESI,# instruction
		DWORD theValue = *(DWORD*)(buf + 6);
		if (theValue >= 1 && theValue <= 5) {
			curSel = 6 - theValue;
		}
	}
	if (curSel == (UINT_PTR)-1) {
		updateStaticText(L"The current state of GetVersionForBattle function is corrupt.");
		return;
	}
	
	if (curSel == 5) {
		if (!ReadProcessMemoryPtr(cleanup.proc, (LPCVOID)((BYTE*)info.lpBaseOfDll + isVer1_10OrHigherPlace), buf, 5, &bytesRead)) {
			logError("Failed to read isVer1_10OrHigher code at offset 0x%.8x", isVer1_10OrHigherPlace);
			return;
		}
		if (buf[0] != 0xb8) {
			curSel = -1;
		} else {
			DWORD theValue = *(DWORD*)(buf + 1);
			if (theValue != 0 && theValue != 1) {
				curSel = (UINT_PTR)-1;
			} else if (theValue == 0) {
				curSel = 6;
			}
		}
		
		if (curSel == (UINT_PTR)-1) {
			updateStaticText(L"The current state of isVer1_10OrHigher function is corrupt.");
			return;
		}
	}
	
	updateStaticText(L"");
	HDC hdc = GetDC(mainWindow);
	HGDIOBJ oldObj = SelectObject(hdc, (HGDIOBJ)font);
	SIZE textSz{0};
	const wchar_t testTxt[] = L"Thisshldbelongenuf";
	GetTextExtentPoint32W(hdc, testTxt, _countof(testTxt) - 1, &textSz);
	SelectObject(hdc, oldObj);
	ReleaseDC(mainWindow, hdc);
	
	comboBoxHwnd = CreateWindowW(WC_COMBOBOXW, L"Current version:", WS_CHILD | WS_OVERLAPPED | WS_VISIBLE | CBS_DROPDOWNLIST,
		5, 5, textSz.cx + 40, textSz.cy + 10, mainWindow, NULL, hInst, NULL);
	SendMessageW(comboBoxHwnd, WM_SETFONT, (WPARAM)font, TRUE);
	
	// these correspond to items in enum ComboBoxSelection
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"Latest Rev1/2");  // 0
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"25A");  // 1
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"25");  // 2
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"Latest REV1");  // 3
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"20A"); // 4
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"20"); // 5
	SendMessageW(comboBoxHwnd, CB_ADDSTRING, 0, (LPARAM)L"20 pre 1.10"); // 6
	
	prevComboBoxSel = curSel;
	SendMessageW(comboBoxHwnd, CB_SETCURSEL, curSel, 0);
	
}

bool findPlaces(HANDLE proc, MODULEINFO* info) {
	
	if (GetVersionForBattlePlace && isVer1_10OrHigherPlace) return true;
	
	std::vector<BYTE> wholeModule(info->SizeOfImage);
	SIZE_T bytesRead = 0;
	if (!(*ReadProcessMemoryPtr)(proc, (LPCVOID)(info->lpBaseOfDll), wholeModule.data(), info->SizeOfImage, &bytesRead)) {
		WinError winErr;
		std::wstringstream msg;
		msg << L"Failed to read memory from the process at memory location 0x" << std::hex << (DWORD)(info->lpBaseOfDll)
			<< L": " << winErr.getMessage();
		updateStaticText(msg.str().c_str());
		return false;
	}
	
	const char* wholeModuleBegin = (const char*)wholeModule.data();
	const char* wholeModuleEnd = (const char*)wholeModule.data() + wholeModule.size();
	const char* textBegin;
	const char* textEnd;
	
	if (!findSectionBounds(".text", (BYTE*)wholeModuleBegin, (BYTE**)&textBegin, (BYTE**)&textEnd)) {
		updateStaticText(L".text section not found.");
		return false;
	}
	
	if (!GetVersionForBattlePlace) {
		const char* GetVersionForBattlePtr = sigscan(textBegin, textEnd,
			"\x83\xf8\x05\x73\x09\xbe\x01\x00\x00\x00\x8b\xc6\x5e\xc3"  // CMP EAX,#; JNC #; MOV ESI,#; MOV EAX,ESI; POP ESI; RET;
			"\x83\xf8\x06\x73\x09\xbe\x02\x00\x00\x00\x8b\xc6\x5e\xc3"
			"\x83\xf8\x07\x73\x09\xbe\x03\x00\x00\x00\x8b\xc6\x5e\xc3"
			"\x83\xf8\x08\x73\x09\xbe\x04\x00\x00\x00\x8b\xc6\x5e\xc3"
			"\x83\xf8\x09\x73\x1a\xbe\x05\x00\x00\x00\x8b\xc6\x5e\xc3");
		if (!GetVersionForBattlePtr) {
			updateStaticText(L"GetVersionForBattle function not found.");
			return false;
		}
		GetVersionForBattlePtr += 0x46;
		GetVersionForBattlePlace = (DWORD)((GetVersionForBattlePtr - wholeModuleBegin) & 0xffffffff);
	}
	
	if (!isVer1_10OrHigherPlace) {
		const char* isVer1_10OrHigherPtr = sigscan(textBegin, textEnd, Sig{"e8 ?? ?? ?? ?? 85 c0 74 0e e8 ?? ?? ?? ?? 83 78 70 03 73 03 33 c0 c3 b8 ?? 00 00 00 c3"});
		if (!isVer1_10OrHigherPtr) {
			updateStaticText(L"isVer1_10OrHigher function not found.");
			return false;
		}
		isVer1_10OrHigherPtr += 23;
		isVer1_10OrHigherPlace = (DWORD)((isVer1_10OrHigherPtr - wholeModuleBegin) & 0xffffffff);
	}
	
	return true;
	
}


void logError(const char* fmt, ...) {
	static char strbuf[1024] { '\0' };
	static wchar_t wstrbuf[1024] { '\0' };
	va_list args;
	va_start(args, fmt);
	vsnprintf(strbuf, sizeof strbuf, fmt, args);
	va_end(args);
	wchar_t* wptr = wstrbuf;
	for (char* ptr = strbuf; *ptr != '\0'; ++ptr) {
		*wptr = *ptr;
		++wptr;
	}
	*wptr = L'\0';
	updateStaticText(wstrbuf);
}

void updateStaticText(const wchar_t* txt) {
	HDC hdc = GetDC(mainWindow);
	HGDIOBJ oldObj = SelectObject(hdc, (HGDIOBJ)font);
	SIZE textSz{0};
	
	std::vector<HWND> reusableHwnds = ggNotFoundTextHwnd;
	auto reusableHwndIt = reusableHwnds.begin();
	std::wstring buf;
	const wchar_t* ptr = txt;
	int y = 5;
	staticTextHeight = y;
	size_t totalRemainingLen = wcslen(txt);
	const wchar_t* nextNewline = wcschr(txt, L'\n');
	while (totalRemainingLen > 0) {
		
		// I should just use a single static control with SS_LEFT
		const wchar_t* txtToAssign;
		size_t lenToAssign;
		if (totalRemainingLen > 100) {
			const wchar_t* ptrEnd = ptr + 100;
			if (nextNewline && nextNewline - ptr < 100) {
				ptrEnd = nextNewline;
			}
			lenToAssign = ptrEnd - ptr;
			buf.assign(ptr, ptrEnd);
			txtToAssign = buf.c_str();
		} else if (nextNewline) {
			lenToAssign = nextNewline - ptr;
			buf.assign(ptr, nextNewline);
			txtToAssign = buf.c_str();
		} else {
			lenToAssign = totalRemainingLen;
			txtToAssign = ptr;
		}
		
		totalRemainingLen -= lenToAssign;
		ptr += lenToAssign;
		
		GetTextExtentPoint32W(hdc, txtToAssign, lenToAssign, &textSz);
		
		if (reusableHwndIt != reusableHwnds.end()) {
			HWND reusableHwnd = *reusableHwndIt;
			++reusableHwndIt;
			SetWindowPos(reusableHwnd, NULL, 5, y, textSz.cx, textSz.cy, SWP_NOOWNERZORDER | SWP_NOZORDER);
			SetWindowTextW(reusableHwnd, txtToAssign);
		} else {
			HWND newHwnd = CreateWindowW(WC_STATICW, txtToAssign,
				WS_CHILD | WS_OVERLAPPED | WS_VISIBLE,
				5, y, textSz.cx, textSz.cy, mainWindow, NULL, hInst, NULL);
			ggNotFoundTextHwnd.push_back(newHwnd);
			SendMessageW(newHwnd, WM_SETFONT, (WPARAM)font, TRUE);
		}
		
		y += textSz.cy;
		staticTextHeight = y;
		if (*ptr == L'\n') {
			++ptr;
			--totalRemainingLen;
		}
		
		while (*ptr == L'\n') {
			y += textSz.cy;
			++ptr;
			--totalRemainingLen;
		}
		
		if (nextNewline && nextNewline < ptr) {
			nextNewline = wcschr(ptr, L'\n');
		}
	}
	
	while (reusableHwndIt != reusableHwnds.end()) {
		DestroyWindow(*reusableHwndIt);
		++reusableHwndIt;
	}
	
	SelectObject(hdc, oldObj);
	ReleaseDC(mainWindow, hdc);
	
	if (comboBoxHwnd) {
		SetWindowPos(comboBoxHwnd, NULL, 5, staticTextHeight + 5, 0, 0, SWP_NOOWNERZORDER | SWP_NOZORDER | SWP_NOSIZE);
	}
	
}

const char* sigscan(const char* start, const char* end, const char* sig, const char* mask) {
    const char* startPtr = start;
    const size_t maskLen = strlen(mask);
    if (memchr(mask, '?', maskLen) == nullptr) {
    	return sigscan(start, end, sig, maskLen);
    }
    const size_t seekLength = end - start - maskLen + 1;
    for (size_t seekCounter = seekLength; seekCounter != 0; --seekCounter) {
        const char* stringPtr = startPtr;

        const char* sigPtr = sig;
        for (const char* maskPtr = mask; true; ++maskPtr) {
            const char maskPtrChar = *maskPtr;
            if (maskPtrChar != '?') {
                if (maskPtrChar == '\0') return startPtr;
                if (*sigPtr != *stringPtr) break;
            }
            ++sigPtr;
            ++stringPtr;
        }
        ++startPtr;
    }
    return nullptr;
}

const char* sigscan(const char* start, const char* end, const char* sig, size_t sigLength) {
	
	// Boyer-Moore-Horspool substring search
	// A table containing, for each symbol in the alphabet, the number of characters that can safely be skipped
	size_t step[256];
	for (int i = 0; i < _countof(step); ++i) {
		step[i] = sigLength;
	}
	for (size_t i = 0; i < sigLength - 1; i++) {
		step[(BYTE)sig[i]] = sigLength - 1 - i;
	}
	
	BYTE pNext;
	end -= sigLength;
	for (const char* p = start; p <= end; p += step[pNext]) {
		int j = sigLength - 1;
		pNext = *(BYTE*)(p + j);
		if (sig[j] == (char)pNext) {
			for (--j; j >= 0; --j) {
				if (sig[j] != *(char*)(p + j)) {
					break;
				}
			}
			if (j < 0) {
				return p;
			}
		}
	}

	return nullptr;
}

void onComboSelChanged() {
	
	updateStaticText(L"");
	
	int curSel = SendMessageW(comboBoxHwnd, CB_GETCURSEL, 0, 0);
	if (curSel == prevComboBoxSel) return;
	int oldComboBoxSel = prevComboBoxSel;
	prevComboBoxSel = curSel;
	
	DWORD threadId = 0;
	DWORD procId = findOpenGgProcess(&threadId);
	if (!procId) {
		DestroyWindow(comboBoxHwnd);
		comboBoxHwnd = NULL;
		SetTimer(mainWindow, 1, 1000, NULL);
		return;
	}
	
	struct Cleanup {
		HANDLE proc = NULL;
		HANDLE thread = NULL;
		bool threadSuspended = false;
		LPVOID vpPtr = NULL;
		SIZE_T vpSize = 0;
		DWORD vpOldProtect = 0;
		~Cleanup() {
			unprotect();
			if (thread) {
				if (threadSuspended) {
					#ifdef _DEBUG
					// during development this app would crash or freeze before resuming the process
					while (true) {
						int previousSuspendCount = (*ResumeThreadPtr)(thread);
						if (previousSuspendCount == 1 || previousSuspendCount == -1) break;
					}
					#else
					(*ResumeThreadPtr)(thread);
					#endif
				}
				(*CloseHandlePtr)(thread);
			}
			if (proc) {
				(*CloseHandlePtr)(proc);
			}
		}
		BOOL changeProtect(LPVOID addr, SIZE_T size, DWORD protect) {
			vpPtr = addr;
			vpSize = size;
			BOOL result = (*VirtualProtectExPtr)(proc, addr, size, protect, &vpOldProtect);
			if (!result) {
				vpPtr = NULL;
			}
			return result;
		}
		void unprotect() {
			if (vpPtr) {
				DWORD evenOlderProtect;
				(*VirtualProtectExPtr)(proc, vpPtr, vpSize, vpOldProtect, &evenOlderProtect);
				vpPtr = NULL;
			}
		}
	} cleanup;
	
	MODULEINFO info;
	if (!openGGProcAndGetModuleInfo(procId, &cleanup.proc, &info)) return;
	if (!findPlaces(cleanup.proc, &info)) return;
	
	std::vector<char> vec;
	OpenThreadPtr = (HANDLE (__stdcall*)(DWORD, BOOL, DWORD))GetProcAddress(kernel32, unscramble(vec, OpenThreadName, OpenThreadKey));
	cleanup.thread = (*OpenThreadPtr)(THREAD_GET_CONTEXT
		| THREAD_QUERY_INFORMATION  // MSDN GetThreadContext: Windows XP or Windows Server 2003: The handle must also have THREAD_QUERY_INFORMATION access.
		| THREAD_SUSPEND_RESUME, FALSE, threadId);
	if (!cleanup.thread) {
		WinError winErr;
		std::wstring msg = L"Failed to gain access to the main thread: ";
		msg += winErr.getMessage();
		updateStaticText(msg.c_str());
		return;
	}
	
	#if defined( _WIN64 )
	Wow64SuspendThreadPtr = (DWORD (__stdcall*)(HANDLE))GetProcAddress(kernel32, unscramble(vec, Wow64SuspendThreadName, Wow64SuspendThreadKey));
	Wow64GetThreadContextPtr = (DWORD (__stdcall*)(HANDLE, PWOW64_CONTEXT))GetProcAddress(kernel32, unscramble(vec, Wow64GetThreadContextName, Wow64GetThreadContextKey));
	#else
	SuspendThreadPtr = (DWORD (__stdcall*)(HANDLE))GetProcAddress(kernel32, unscramble(vec, SuspendThreadName, SuspendThreadKey));
	GetThreadContextPtr = (DWORD (__stdcall*)(HANDLE, LPCONTEXT))GetProcAddress(kernel32, unscramble(vec, GetThreadContextName, GetThreadContextKey));
	#endif
	
	ResumeThreadPtr = (DWORD (__stdcall*)(HANDLE))GetProcAddress(kernel32, unscramble(vec, ResumeThreadName, ResumeThreadKey));
	
	int numberOfTries = 2;
	while (numberOfTries > 0) {
		if (
			#if defined( _WIN64 )
			(*Wow64SuspendThreadPtr)
			#else
			(*SuspendThreadPtr)
			#endif
			(cleanup.thread) == (DWORD)-1
		) {
			WinError winErr;
			std::wstring msg = L"Failed to suspend the main thread: ";
			msg += winErr.getMessage();
			updateStaticText(msg.c_str());
			return;
		}
		cleanup.threadSuspended = true;
		
		#if defined( _WIN64 )
		WOW64_CONTEXT ctx;
		#else
		CONTEXT ctx;
		#endif
		ctx.ContextFlags = CONTEXT_CONTROL;
		
		if (!
			#if defined( _WIN64 )
			(*Wow64GetThreadContextPtr)
			#else
			(*GetThreadContextPtr)
			#endif
			(cleanup.thread, &ctx)
		) {
			WinError winErr;
			std::wstring msg = L"Failed to get context of the main thread: ";
			msg += winErr.getMessage();
			updateStaticText(msg.c_str());
			return;
		}
		
		if (ctx.Eip > (DWORD)info.lpBaseOfDll + GetVersionForBattlePlace
				&& ctx.Eip < (DWORD)info.lpBaseOfDll + GetVersionForBattlePlace + 17) {
			(*ResumeThreadPtr)(cleanup.thread);
			cleanup.threadSuspended = false;
			--numberOfTries;
			Sleep(1);
		} else {
			break;
		}
	}
	if (numberOfTries == 0) {
		updateStaticText(L"The main thread seems to be frozen in debug on the exact place I'm trying to patch.");
		SendMessageW(comboBoxHwnd, CB_SETCURSEL, oldComboBoxSel, 0);
		return;
	}
	
	VirtualProtectExPtr = (BOOL (__stdcall*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD))
		GetProcAddress(kernel32, unscramble(vec, VirtualProtectExName, VirtualProtectExKey));
	
	WriteProcessMemoryPtr = (BOOL (__stdcall*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))
		GetProcAddress(kernel32, unscramble(vec, WriteProcessMemoryName, WriteProcessMemoryKey));
	
	char newVal;
	
	SIZE_T bytesWritten = 0;
	if (!(oldComboBoxSel == ComboBoxSelection::CBSEL_20 && curSel == ComboBoxSelection::CBSEL_20PRE1_10
			|| curSel == ComboBoxSelection::CBSEL_20 && oldComboBoxSel == ComboBoxSelection::CBSEL_20PRE1_10)) {
		
		if (curSel == ComboBoxSelection::CBSEL_20PRE1_10) {
			newVal = 1;
		} else {
			newVal = 6 - curSel;
		}
		
		Sig buf;
		if (oldComboBoxSel == ComboBoxSelection::CBSEL_LATEST
				|| curSel == ComboBoxSelection::CBSEL_LATEST) {
			if (oldComboBoxSel == ComboBoxSelection::CBSEL_LATEST) {
				
				int IsRevelator2_OptionOffset;
				SIZE_T bytesRead = 0;
				if (!(*ReadProcessMemoryPtr)(cleanup.proc, (LPCVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace + 1), &IsRevelator2_OptionOffset, 4, &bytesRead)) {
					WinError winErr;
					std::wstringstream msg;
					msg << L"Failed to read the offset of IsRevelator2_Option function call at offset 0x" << std::hex << GetVersionForBattlePlace
						<< L": " << winErr.getMessage();
					updateStaticText(msg.str().c_str());
					return;
				}
				
				buf = Sig{
					"90 90 90 90 90 "  // nop out the CALL IsRevelator2_Option, so that if he was inside of it, when he comes back he does our new instructions
					"be 00 00 00 00 "  // MOV ESI,####; we'll write an actual number very soon
					"eb 05 "  // JMP 5
					"e8 00 00 00 00"  // we'll place the original CALL instruction here. We'll write an actual call offset very soon
				};
				
				buf.sig[6] = newVal;
				
				IsRevelator2_OptionOffset -= 12;
				memcpy(buf.sig.data() + 13, &IsRevelator2_OptionOffset, 4);
				
			} else if (curSel == ComboBoxSelection::CBSEL_LATEST) {
				
				int IsRevelator2_OptionOffset;
				SIZE_T bytesRead = 0;
				if (!(*ReadProcessMemoryPtr)(cleanup.proc, (LPCVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace + 13), &IsRevelator2_OptionOffset, 4, &bytesRead)) {
					WinError winErr;
					std::wstringstream msg;
					msg << L"Failed to read the offset of IsRevelator2_Option function call at offset 0x" << std::hex << GetVersionForBattlePlace + 13
						<< L": " << winErr.getMessage();
					updateStaticText(msg.str().c_str());
					return;
				}
				
				buf = Sig{
					"e8 00 00 00 00 "  // CALL IsRevelator2_Option, we'll write an actual offset very soon
					"8b f0 "  // MOV ESI,EAX
					"f7 de "  // NEG ESI
					"1b f6 "  // SBB ESI,ESI
					"83 e6 fd "  // AND ESI,0xfffffffd
					"83 c6 03 "  // ADD ESI,0x3
				};
				IsRevelator2_OptionOffset += 12;
				memcpy(buf.sig.data() + 1, &IsRevelator2_OptionOffset, 4);
			}
			
			if (!cleanup.changeProtect((LPVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace), 17, PAGE_EXECUTE_READWRITE)) {
				WinError winErr;
				std::wstringstream msg;
				msg << L"Failed to change protection level of GetVersionForBattle's code at offset 0x" << std::hex << GetVersionForBattlePlace
					<< L": " << winErr.getMessage();
				updateStaticText(msg.str().c_str());
				return;
			}
			
			if (!(*WriteProcessMemoryPtr)(cleanup.proc, (LPVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace), buf.sig.data(), 17, &bytesWritten)) {
				WinError winErr;
				std::wstringstream msg;
				msg << L"Failed to overwrite function GetVersionForBattle at offset 0x" << std::hex << GetVersionForBattlePlace
					<< L": " << winErr.getMessage();
				updateStaticText(msg.str().c_str());
				return;
			}
			
			cleanup.unprotect();
			
		} else {
			
			if (!cleanup.changeProtect((LPVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace + 6), 1, PAGE_EXECUTE_READWRITE)) {
				WinError winErr;
				std::wstringstream msg;
				msg << L"Failed to change protection level of GetVersionForBattle's code at offset 0x" << std::hex << GetVersionForBattlePlace + 6
					<< L": " << winErr.getMessage();
				updateStaticText(msg.str().c_str());
				return;
			}
			
			if (!(*WriteProcessMemoryPtr)(cleanup.proc, (LPVOID)((BYTE*)info.lpBaseOfDll + GetVersionForBattlePlace + 6), &newVal, 1, &bytesWritten)) {
				WinError winErr;
				std::wstringstream msg;
				msg << L"Failed to overwrite function GetVersionForBattle at offset 0x" << std::hex << GetVersionForBattlePlace + 6
					<< L": " << winErr.getMessage();
				updateStaticText(msg.str().c_str());
				return;
			}
			
			cleanup.unprotect();
			
		}
	}
	
	if (oldComboBoxSel == ComboBoxSelection::CBSEL_20PRE1_10 || curSel == ComboBoxSelection::CBSEL_20PRE1_10) {
		
		newVal = curSel == ComboBoxSelection::CBSEL_20PRE1_10 ? 0 : 1;
		
		if (!cleanup.changeProtect((LPVOID)((BYTE*)info.lpBaseOfDll + isVer1_10OrHigherPlace + 1), 1, PAGE_EXECUTE_READWRITE)) {
			WinError winErr;
			std::wstringstream msg;
			msg << L"Failed to change protection level of isVer1_10OrHigher's code at offset 0x" << std::hex << isVer1_10OrHigherPlace + 1
				<< L": " << winErr.getMessage();
			updateStaticText(msg.str().c_str());
			return;
		}
		
		if (!(*WriteProcessMemoryPtr)(cleanup.proc, (LPVOID)((BYTE*)info.lpBaseOfDll + isVer1_10OrHigherPlace + 1), &newVal, 1, &bytesWritten)) {
			WinError winErr;
			std::wstringstream msg;
			msg << L"Failed to overwrite function isVer1_10OrHigher at offset 0x" << std::hex << isVer1_10OrHigherPlace + 1
				<< L": " << winErr.getMessage();
			updateStaticText(msg.str().c_str());
			return;
		}
		
		cleanup.unprotect();
		
	}
	
}

bool openGGProcAndGetModuleInfo(DWORD procId, HANDLE* procPtr, MODULEINFO* info) {
	std::vector<char> vec;
	vec.resize(4);
	
	// throwing off sigscans
	DWORD value = PROCESS_ALL_ACCESS;
	memcpy(vec.data(), &value, 4);
	scramble(vec, 988787287);
	scramble(vec, 988787287);
	DWORD access = *(DWORD*)vec.data();
	
	memcpy(vec.data(), &procId, 4);
	scramble(vec, 5775793);
	scramble(vec, 5775793);
	DWORD arg3 = *(DWORD*)vec.data();
	
	if (!kernel32) {
		kernel32 = LoadLibraryA(unscramble(vec, kernel32Name, kernel32Key));
	}
	OpenProcessPtr = (HANDLE (__stdcall*)(DWORD, BOOL, DWORD))GetProcAddress(kernel32, unscramble(vec, OpenProcessName, OpenProcessKey));
	CloseHandlePtr = (BOOL (__stdcall*)(HANDLE))GetProcAddress(kernel32, unscramble(vec, CloseHandleName, CloseHandleKey));
	HANDLE proc = (*OpenProcessPtr)(access, FALSE, arg3);
	if (!proc || proc == INVALID_HANDLE_VALUE) {
		WinError winErr;
		std::wstring msg = L"Failed to open process: ";
		msg += winErr.getMessage();
		updateStaticText(msg.c_str());
		return false;
	}
	*procPtr = proc;
	
	EnumProcessModulesExPtr = (BOOL (__stdcall*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD))
		GetProcAddress(kernel32, unscramble(vec, EnumProcessModulesExName, EnumProcessModulesExKey));
	
	if (!EnumProcessModulesExPtr) {
		if (!Psapi) {
			Psapi = LoadLibraryA(unscramble(vec, PsapiName, PsapiKey));
		}
		
		EnumProcessModulesExPtr = (BOOL (__stdcall*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD))
			GetProcAddress(Psapi, unscramble(vec, EnumProcessModulesExName, EnumProcessModulesExKey));
		
	}
	
	HMODULE hModule;
	DWORD bytesReturned = 0;
	if (!(*EnumProcessModulesExPtr)(proc, &hModule, sizeof HMODULE, &bytesReturned, LIST_MODULES_32BIT)) {
		WinError winErr;
		std::wstring msg = L"Failed to enum modules: ";
		msg += winErr.getMessage();
		updateStaticText(msg.c_str());
		return false;
	}
	if (bytesReturned == 0) {
		updateStaticText(L"The process has 0 modules.");
		return false;
	}
	
	GetModuleInformationPtr = (BOOL (__stdcall*)(HANDLE, HMODULE, LPMODULEINFO, DWORD))
		GetProcAddress(kernel32, unscramble(vec, GetModuleInformationName, GetModuleInformationKey));
	
	if (!GetModuleInformationPtr) {
		if (!Psapi) {
			Psapi = LoadLibraryA(unscramble(vec, PsapiName, PsapiKey));
		}
		
		GetModuleInformationPtr = (BOOL (__stdcall*)(HANDLE, HMODULE, LPMODULEINFO, DWORD))
			GetProcAddress(Psapi, unscramble(vec, GetModuleInformationName, GetModuleInformationKey));
	}
	
	if (!(*GetModuleInformationPtr)(proc, hModule, info, sizeof(MODULEINFO))) {
		WinError winErr;
		std::wstring msg = L"Failed to get module information: ";
		msg += winErr.getMessage();
		updateStaticText(msg.c_str());
		return false;
	}
	ReadProcessMemoryPtr = (BOOL (__stdcall*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))
		GetProcAddress(kernel32, unscramble(vec, ReadProcessMemoryName, ReadProcessMemoryKey));
	
	return true;
}
