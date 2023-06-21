#include "Join.h"

static char joinRemoteAddress[512] = "127.0.0.1";
char joinLocalIpAddress[512] = "127.0.0.1";
std::string joinEmail = "";
bool checkDuplicateJoinEmail = false;

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
                BOOST_LOG_TRIVIAL(info) << "RemoteAddress : " << joinRemoteAddress << "LocalIpAddress : " << joinLocalIpAddress;
                break;
            }
        }
    }
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

// Function to perform join logic
bool PerformJoin(HWND hDlg)
{
    // Get email text
    std::string email;
    if (!getControlText(hDlg, IDC_JOIN_E_EMAIL, email))
    {
        BOOST_LOG_TRIVIAL(error) << "Email is empty";
        MessageBox(hDlg, TEXT("Email is empty"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Check if the email is a duplicate
    // Check if the email matches the newEmail
    if (!checkDuplicateJoinEmail || (email != joinEmail))
    {
        checkDuplicateJoinEmail = false;
        joinEmail = "";
        MessageBox(hDlg, TEXT("Please click the [Duplicate Check] button"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Get password text
    std::string password;
    if (!getControlText(hDlg, IDC_JOIN_E_PASSWORD, password))
    {
        BOOST_LOG_TRIVIAL(error) << "Password is empty";
        MessageBox(hDlg, TEXT("Password is empty"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    else if (!validatePassword(password)) {
        BOOST_LOG_TRIVIAL(error) << "Password is invalid";
        MessageBox(hDlg, TEXT("Password is invalid"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Get confirm password text
    std::string cPassword;
    if (!getControlText(hDlg, IDC_JOIN_E_CONFIRMPASSWORD, cPassword))
    {
        BOOST_LOG_TRIVIAL(error) << "Confirm password is empty";
        MessageBox(hDlg, TEXT("Confirm password is empty"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    else if (!validatePassword(cPassword)) {
        BOOST_LOG_TRIVIAL(error) << "Confirm password is invalid";
        MessageBox(hDlg, TEXT("Confirm password is invalid"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Compare the entered password with loginPassword
    if (password != cPassword)
    {
        BOOST_LOG_TRIVIAL(error) << "Password and confirmation password do not match";
        MessageBox(hDlg, TEXT("Password and confirmation password do not match"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
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
        BOOST_LOG_TRIVIAL(error) << "first name is empty";
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
        BOOST_LOG_TRIVIAL(error) << "last name is empty";
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
        BOOST_LOG_TRIVIAL(error) << "ip address is empty";
        MessageBox(hDlg, TEXT("IP address is empty"), TEXT("IP address Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // password, cpassword, email, fName, lName, addr
    std::string requestString = "email=" + email + "&password=" + password + "&confirm_password=" + cPassword + "&ip_address=" + addr + "&first_name=" + fName + "&last_name=" + lName;

    unsigned int status_code;
    std::map<std::string, std::string> response;
    int rc = request("POST", "/api/user/signup/", requestString, "", &status_code, response);

    if (rc != 0 || status_code != 200)
    {
        BOOST_LOG_TRIVIAL(error) << "rc =" << rc << " status_code = " << status_code;
        MessageBox(hDlg, TEXT("Error is occurred, Please check the input value"), TEXT("Error from server"), MB_OK | MB_ICONERROR);
        return false;
    }

    BOOST_LOG_TRIVIAL(info) << response["message"];
    
    std::string successMessage = response["message"];

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wstr = converter.from_bytes(successMessage);

    BOOST_LOG_TRIVIAL(info) << "User created successfully";
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
            std::string email;
            checkDuplicateJoinEmail = checkEmail(hDlg, IDC_JOIN_E_EMAIL, email);
            if (checkDuplicateJoinEmail)
            {
                joinEmail = email;
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
