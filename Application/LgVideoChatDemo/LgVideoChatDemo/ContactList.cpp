#include "BoostLog.h"
#include "ContactList.h"
#include "eWID.h"

#include <string>
#include <regex>

static HWND hContactListWnd;
static void AddContactListInfo(void);
static std::wstring ExtractIPAddress(const std::wstring& input);
static void ConvertToWideCharArray(const std::wstring& input, wchar_t* output, std::size_t size);
static LPSTR ConvertWideCharToLPSTR(const wchar_t* wideCharString);

LRESULT CreateContactListWindow(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam, RECT rt)
{
	const LONG offset = 20;

	// Label
	CreateWindow(_T("STATIC"),
		_T("Contact List"),
		WS_VISIBLE | WS_CHILD,
		rt.left, rt.top, rt.right, offset,
		hWnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
	// listbox
	hContactListWnd = CreateWindow(_T("LISTBOX"), NULL,
		WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY | WS_VSCROLL,
		rt.left, rt.top + offset, rt.right, rt.bottom - offset,
		hWnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);

	AddContactListInfo();

	return 1;
}

LRESULT DoubleClickContactListEventHandler(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	HWND hEditWnd;
	HWND hListBox = (HWND)lParam;

	int selectedIndex = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
	if (selectedIndex != LB_ERR)
	{
		wchar_t address[256], ipaddr[256];
		SendMessage(hListBox, LB_GETTEXT, selectedIndex, (LPARAM)address);
		ConvertToWideCharArray(ExtractIPAddress(std::wstring(address)), ipaddr, 256);

		// Update Text to EditBox
		hEditWnd = GetDlgItem(hWnd, IDC_EDIT_REMOTE);		
		SetWindowTextA(hEditWnd, ConvertWideCharToLPSTR(ipaddr));
	}

	return 0;
}

static void AddContactListInfo(void)
{
	// 주소 목록 추가
	const wchar_t* contectList[] = {
		L"1. John Smith - john.smith@example.com - 192.168.0.126",
		L"2. Emily Johnson - emily.johnson@example.com - 10.0.0.1",
		L"3. Michael Williams - michael.williams@example.com - 172.16.0.1",
		L"4. Emma Brown - emma.brown@example.com - 192.168.1.1",
		L"5. Daniel Jones - daniel.jones@example.com - 10.0.0.2",
		L"6. Olivia Davis - olivia.davis@example.com - 172.16.0.2",
		L"7. Matthew Miller - matthew.miller@example.com - 192.168.2.1",
		L"8. Ava Wilson - ava.wilson@example.com - 10.0.0.3",
		L"9. Sophia Taylor - sophia.taylor@example.com - 172.16.0.3",
		L"10. William Anderson - william.anderson@example.com - 192.168.3.1",
		L"11. Isabella Martinez - isabella.martinez@example.com - 10.0.0.4",
		L"12. Ethan Thomas - ethan.thomas@example.com - 172.16.0.4",
		L"13. Mia Garcia - mia.garcia@example.com - 192.168.4.1",
		L"14. James Robinson - james.robinson@example.com - 10.0.0.5",
		L"15. Charlotte Clark - charlotte.clark@example.com - 172.16.0.5",
		L"16. Benjamin Rodriguez - benjamin.rodriguez@example.com - 192.168.5.1",
		L"17. Amelia Lewis - amelia.lewis@example.com - 10.0.0.6",
		L"18. Harper Lee - harper.lee@example.com - 172.16.0.6",
		L"19. Henry Walker - henry.walker@example.com - 192.168.6.1",
		L"20. Evelyn Hall - evelyn.hall@example.com - 10.0.0.7"
	};

	for (int i = 0; i < sizeof(contectList) / sizeof(contectList[0]); ++i)
		SendMessage(hContactListWnd, LB_ADDSTRING, 0, (LPARAM)contectList[i]);

}

static std::wstring ExtractIPAddress(const std::wstring& input)
{
	// IP 주소 추출을 위한 정규식 패턴
	std::wregex pattern(L"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

	// 정규식 패턴과 매치되는 첫 번째 IP 주소 추출
	std::wsmatch matches;
	if (std::regex_search(input, matches, pattern))
	{
		// 매치된 IP 주소 반환
		return matches[0].str();
	}

	// 매치된 IP 주소가 없을 경우 빈 문자열 반환
	return L"";
}

static void ConvertToWideCharArray(const std::wstring& input, wchar_t* output, std::size_t size)
{
	if (output != nullptr && size > 0)
	{
		wcsncpy_s(output, size, input.c_str(), _TRUNCATE);
	}
}

static LPSTR ConvertWideCharToLPSTR(const wchar_t* wideCharString)
{
	int bufferSize = WideCharToMultiByte(CP_ACP, 0, wideCharString, -1, nullptr, 0, nullptr, nullptr);
	if (bufferSize == 0)
	{
		// Failed to determine the required buffer size
		return nullptr;
	}

	LPSTR lpstrString = new CHAR[bufferSize];
	if (WideCharToMultiByte(CP_ACP, 0, wideCharString, -1, lpstrString, bufferSize, nullptr, nullptr) == 0)
	{
		// Failed to convert wide character string to LPSTR
		delete[] lpstrString;
		return nullptr;
	}

	return lpstrString;
}