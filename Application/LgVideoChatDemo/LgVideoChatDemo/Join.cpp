#include "framework.h"
#include <Commctrl.h>
#include <atlstr.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <Windows.h>

#include <string>
#include <codecvt>
#include "Join.h"
#include "BackendHttpsClient.h"

static char joinRemoteAddress[512] = "127.0.0.1";
char joinLocalIpAddress[512] = "127.0.0.1";

bool startsWith(const std::string& str, const std::string& prefix) {
    if (str.length() < prefix.length()) {
        return false;
    }

    return str.compare(0, prefix.length(), prefix) == 0;
}

static void SetHostAddr(void)
{
    // Get the local hostname
    struct addrinfo* _addrinfo;
    struct addrinfo* _res;
    char _address[INET6_ADDRSTRLEN];
    char szHostName[255];
    gethostname(szHostName, sizeof(szHostName));
    getaddrinfo(szHostName, NULL, 0, &_addrinfo);

    for (_res = _addrinfo; _res != NULL; _res = _res->ai_next)
    {
        if (_res->ai_family == AF_INET)
        {
            if (NULL == inet_ntop(AF_INET,
                &((struct sockaddr_in*)_res->ai_addr)->sin_addr,
                _address,
                sizeof(_address))
                )
            {
                perror("inet_ntop");
                return;
            }

            if (startsWith(_address, "192.168.0."))
            {
                strcpy_s(joinRemoteAddress, sizeof(joinRemoteAddress), _address);
                strcpy_s(joinLocalIpAddress, sizeof(joinLocalIpAddress), _address);
                std::cout << "RemoteAddress : " << joinRemoteAddress << "LocalIpAddress : " << joinLocalIpAddress << std::endl;
                break;
            }
        }
    }
}


// Function to check if the given email is a duplicate
bool isDuplicateEmailInJoin(const std::string& email) {
    unsigned int rc = 0;
    rc = backendCheckEmail(email);
    if (rc == 403) {
        return true;
    }
    return false;
}

// Function to check if the given email is valid
bool isValidEmailInJoin(const std::string& email) {
    // Regular expression pattern for email validation
    const std::regex pattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return std::regex_match(email, pattern);
}

void EnableEdit(HWND hDlg, BOOL bEnable)
{
    HWND hEditPassOTP = GetDlgItem(hDlg, IDC_JOIN_E_PASSWORD);
    HWND hEditCPassOTP = GetDlgItem(hDlg, IDC_JOIN_E_CONFIRMPASSWORD);
    HWND hEditFNameOTP = GetDlgItem(hDlg, IDC_JOIN_E_FIRSTNAME);
    HWND hEditLNameOTP = GetDlgItem(hDlg, IDC_JOIN_E_LASTNAME);
    HWND hEditAddrOTP = GetDlgItem(hDlg, IDC_JOIN_E_ADDRESS);

    // IDC_LOGIN_E_OTP Edit 창을 활성화
    EnableWindow(hEditPassOTP, bEnable);
    EnableWindow(hEditCPassOTP, bEnable);
    EnableWindow(hEditFNameOTP, bEnable);
    EnableWindow(hEditLNameOTP, bEnable);
    EnableWindow(hEditAddrOTP, bEnable);

}

// Function to perform email validation and duplicate check
bool checkEmailInJoin(HWND hDlg) {
    HWND hEmailEdit = GetDlgItem(hDlg, IDC_JOIN_E_EMAIL);
    int newEmailLength = GetWindowTextLength(hEmailEdit);
    std::string email;

    if (newEmailLength == 0) {
        std::cout << "Email cannot be empty." << std::endl;
        MessageBox(hDlg, TEXT("Email cannot be empty"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    else {
        std::vector<char> buffer(newEmailLength + 1);
        GetWindowTextA(hEmailEdit, buffer.data(), newEmailLength + 1);
        email = buffer.data();
        std::cout << "Email - " << email << std::endl;
    }

    if (!isValidEmailInJoin(email)) {
        std::cout << "Invalid email format." << std::endl;
        MessageBox(hDlg, TEXT("Invalid email format"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    if (isDuplicateEmailInJoin(email)) {
        std::cout << "Duplicate email found." << std::endl;
        MessageBox(hDlg, TEXT("Duplicate email found"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    return true;
}

void removeQuotes(std::string& str) {
    str.erase(std::remove(str.begin(), str.end(), '\"'), str.end());
}

// Function to perform join logic
bool PerformJoin(HWND hDlg)
{
    // Get password text
    HWND hPasswordEdit = GetDlgItem(hDlg, IDC_JOIN_E_PASSWORD);
    int passwordLength = GetWindowTextLength(hPasswordEdit);
    std::string password;
    if (passwordLength > 0)
    {
        std::vector<char> buffer(passwordLength + 1);
        GetWindowTextA(hPasswordEdit, buffer.data(), passwordLength + 1);
        password = buffer.data();
    }
    else
    {
        std::cout << "password is empty" << std::endl;
        MessageBox(hDlg, TEXT("Password is empty"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    
    HWND hCPasswordEdit = GetDlgItem(hDlg, IDC_JOIN_E_CONFIRMPASSWORD);
    int cPasswordLength = GetWindowTextLength(hCPasswordEdit);
    std::string cPassword;
    if (cPasswordLength > 0)
    {
        std::vector<char> buffer(cPasswordLength + 1);
        GetWindowTextA(hCPasswordEdit, buffer.data(), cPasswordLength + 1);
        cPassword = buffer.data();
    }
    else
    {
        std::cout << "confirm password is empty" << std::endl;
        MessageBox(hDlg, TEXT("Confirm password is empty"), TEXT("Confirm password Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Compare the entered password with loginPassword
    if (password != cPassword)
    {
        std::cout << "Password is not same" << std::endl;
        MessageBox(hDlg, TEXT("Password is not same"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    HWND hEmailEdit = GetDlgItem(hDlg, IDC_JOIN_E_EMAIL);
    int emailLength = GetWindowTextLength(hEmailEdit);
    std::string email;
    if (emailLength > 0)
    {
        std::vector<char> buffer(emailLength + 1);
        GetWindowTextA(hEmailEdit, buffer.data(), emailLength + 1);
        email = buffer.data();
    }
    else
    {
        std::cout << "email is empty" << std::endl;
        MessageBox(hDlg, TEXT("Email is empty"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    HWND hFNameEdit = GetDlgItem(hDlg, IDC_JOIN_E_FIRSTNAME);
    int fnameLength = GetWindowTextLength(hFNameEdit);
    std::string fName;
    if (fnameLength > 0)
    {
        std::vector<char> buffer(fnameLength + 1);
        GetWindowTextA(hFNameEdit, buffer.data(), fnameLength + 1);
        fName = buffer.data();
    }
    else
    {
        std::cout << "first name is empty" << std::endl;
        MessageBox(hDlg, TEXT("First name is empty"), TEXT("First name Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    HWND hLNameEdit = GetDlgItem(hDlg, IDC_JOIN_E_LASTNAME);
    int lnameLength = GetWindowTextLength(hLNameEdit);
    std::string lName;
    if (lnameLength > 0)
    {
        std::vector<char> buffer(lnameLength + 1);
        GetWindowTextA(hLNameEdit, buffer.data(), lnameLength + 1);
        lName = buffer.data();
    }
    else
    {
        std::cout << "last name is empty" << std::endl;
        MessageBox(hDlg, TEXT("Last name is empty"), TEXT("Last name Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    HWND hAddrEdit = GetDlgItem(hDlg, IDC_JOIN_E_ADDRESS);
    int addrLength = GetWindowTextLength(hAddrEdit);
    std::string addr;
    if (addrLength > 0)
    {
        std::vector<char> buffer(addrLength + 1);
        GetWindowTextA(hAddrEdit, buffer.data(), addrLength + 1);
        addr = buffer.data();
    }
    else
    {
        std::cout << "ip address is empty" << std::endl;
        MessageBox(NULL, TEXT("IP address is empty"), TEXT("IP address Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // password, cpassword, email, fName, lName, addr
    std::string requestString = "email=" + email + "&password=" + password + "&confirm_password=" + cPassword + "&ip_address=" + addr + "&first_name=" + fName + "&last_name=" + lName;
    std::cout << "requestString : " << requestString << std::endl;

    unsigned int status_code;
    std::map<std::string, std::string> response;
    int rc = request("POST", "/api/user/signup/", requestString, "", &status_code, response);

    if (rc != 0 || status_code != 200)
    {
        std::cout << "rc =" << rc << " status_code = " << status_code << std::endl;
        return false;
    }

    std::cout << response["message"] << std::endl;
    for (const auto& pair : response) {
        std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
    }

    std::string successMessage = response["message"];
    removeQuotes(successMessage);

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wstr = converter.from_bytes(successMessage);

    std::cout << "User created" << std::endl;
    MessageBox(hDlg, wstr.c_str(), TEXT("User created"), MB_OK);

    return true;
}

void setIPAddr(HWND hDlg)
{
    HWND hAddrEdit = GetDlgItem(hDlg, IDC_JOIN_E_ADDRESS);
    SetHostAddr();
    SetWindowTextA(hAddrEdit, joinRemoteAddress);
}

// Message handler for Join box.
INT_PTR CALLBACK Join(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        setIPAddr(hDlg);
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            if (PerformJoin(hDlg))
            {
                EndDialog(hDlg, IDOK);
            }
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // 취소 버튼을 누르면 다이얼로그를 닫습니다.
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_JOIN_CHECKEMAIL)
        {
            SetHostAddr();
            // IDC_UPDATE_BUTTON_DUPLICATE 버튼 클릭 시 OnButtonOTPClick 함수 호출
            if (checkEmailInJoin(hDlg))
            {
                EnableEdit(hDlg, TRUE);
            }
            else
            {
                EnableEdit(hDlg, FALSE);
            }
            return TRUE;
        }
        break;
    }

    return FALSE;
}
