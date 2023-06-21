#include "Login.h"

std::string loginToken;
std::string accessToken;

// OTP 버튼 상태를 나타내는 변수
bool otpButtonEnabled = true;

// 카운트다운을 표시하는 함수
void ShowCountdown(HWND hDlg)
{
    // 1분을 나타내는 초
    int countdownSeconds = 1 * 60;

    while (countdownSeconds >= 0)
    {
        // 분과 초 계산
        int minutes = countdownSeconds / 60;
        int seconds = countdownSeconds % 60;

        // 텍스트 상자에 카운트다운 표시
        std::wstring countdownText = std::to_wstring(minutes / 10) + std::to_wstring(minutes % 10) + L":" +
            std::to_wstring(seconds / 10) + std::to_wstring(seconds % 10);
        SetDlgItemTextW(hDlg, IDC_LOGIN_T_TIME, countdownText.c_str());

        // 1초 대기
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // 카운트다운 감소
        countdownSeconds--;
    }

    // 카운트다운이 종료되면 OTP 버튼을 다시 활성화
    otpButtonEnabled = true;
    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), TRUE);

}

void OnButtonOTPClick(HWND hDlg)
{
    // IDC_LOGIN_E_OTP Edit 창의 핸들을 가져옴
    HWND hEditOTP = GetDlgItem(hDlg, IDC_LOGIN_E_OTP);

    // IDC_LOGIN_E_OTP Edit 창을 활성화
    EnableWindow(hEditOTP, TRUE);
}

// Function to perform login logic
bool PerformLogin(HWND hDlg)
{
    int rc = 0;
    unsigned int status_code;
    std::map<std::string, std::string> response;

    // Get email text
    std::string email;
    if (!getControlText(hDlg, IDC_LOGIN_E_EMAIL, email))
    {
        BOOST_LOG_TRIVIAL(error) << "Email is empty";
        MessageBox(hDlg, TEXT("Email is empty"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    if (!isValidEmail(email)) {
        BOOST_LOG_TRIVIAL(error) << "Invalid email format";
        MessageBox(hDlg, TEXT("Invalid email format"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Get password text
    std::string password;
    if (!getControlText(hDlg, IDC_LOGIN_E_PASSWORD, password))
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

    // Get OTP text
    std::string input_otp;
    if (!getControlText(hDlg, IDC_LOGIN_E_OTP, input_otp))
    {
        MessageBox(hDlg, TEXT("Please enter OTP"), TEXT("OTP Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    std::cout << "test_sch, login_token: " << loginToken << std::endl;
    std::cout << "test_sch, input_otp: " << input_otp << std::endl;

    // Perform login logic with email, password, and OTP. 서버로 전송
    if (!email.empty() && !password.empty() && !input_otp.empty())
    {
        // Check if the entered email, password, and OTP match the predefined values and generated OTP
        std::string data = "otp=" + input_otp + "&" + "login_token=" + loginToken;
        std::cout << "test_sch, data: " << data << std::endl;

        rc = request("POST", "/api/auth/verify-otp/", data, "", &status_code, response);
        if (status_code == 200)
        {
            // 로그인이 성공하면 true를 반환합니다.
            accessToken = response["access_token"];
            std::cout << "test_sch, access_token: " << accessToken << std::endl;
            std::cout << " tst_sch, login success" << std::endl;
            return true;
        }
        else
        {
            std::cout << " tst_sch, login Fail" << std::endl;
            return false;
        }
    }

    // 입력이 유효하지 않거나 로그인이 실패한 경우에는 false를 반환합니다.
    std::cout << " tst_sch, login Fail" << std::endl;
    return false;
}

// Message handler for Login box.
INT_PTR CALLBACK Login(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            // Perform login
            if (PerformLogin(hDlg))
            {
                // 로그인이 성공하면 알림 창을 띄웁니다.
                MessageBox(hDlg, TEXT("Login successful!"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);

                // 로그인이 성공하면 다이얼로그를 닫습니다.
                EndDialog(hDlg, IDOK);
            }
            else
            {
                // 입력이 유효하지 않거나 로그인이 실패한 경우에 대한 처리
                MessageBox(hDlg, TEXT("Invalid email, password, or OTP."), TEXT("Login Error"), MB_OK | MB_ICONERROR);
            }

            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // 취소 버튼을 누르면 다이얼로그를 닫습니다.
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_BUTTON_OTP) // e-mail, pw 입력 및 otp 생성버튼 click
        {
            int rc = 0;
            unsigned int status_code;
            std::map<std::string, std::string> response;
            // Send GET request
            rc = request("GET", "/", "","",&status_code,response);

            // Get email text
            HWND hEmailEdit = GetDlgItem(hDlg, IDC_LOGIN_E_EMAIL);
            int emailLength = GetWindowTextLength(hEmailEdit);
            std::string email;
            if (emailLength > 0)
            {
                std::vector<char> buffer(emailLength + 1);
                GetWindowTextA(hEmailEdit, buffer.data(), emailLength + 1);
                email = buffer.data();
            }

            // Get password text
            HWND hPasswordEdit = GetDlgItem(hDlg, IDC_LOGIN_E_PASSWORD);
            int passwordLength = GetWindowTextLength(hPasswordEdit);
            std::string password;
            if (passwordLength > 0)
            {
                std::vector<char> buffer(passwordLength + 1);
                GetWindowTextA(hPasswordEdit, buffer.data(), passwordLength + 1);
                password = buffer.data();
            }

            // IDC_BUTTON_OTP 버튼을 누르면 OTP를 생성하고 메일로 발송합니다.
            std::string data = "email=" + email + "&" + "password=" + password;

			rc = request("POST", "/api/auth/login/", data, "", &status_code, response);
            if(status_code == 200)
            {
                loginToken = response["login_token"];
                std::cout << "********** test_sch, loginToken: " << loginToken << std::endl;

                // IDC_BUTTON_OTP 버튼 클릭 시 OnButtonOTPClick 함수 호출
                OnButtonOTPClick(hDlg);

                // OTP 버튼을 비활성화
                otpButtonEnabled = false;
                EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), FALSE);

                // 카운트다운 시작
                std::thread countdownThread(ShowCountdown, hDlg);
                countdownThread.detach();
                return TRUE;
            
            }
            else
            {
                std::cout << " email & pw not matched" << std::endl;
                MessageBox(hDlg, TEXT("email & pw not matched"), TEXT("OTP Error"), MB_OK | MB_ICONERROR);
                return FALSE;
            }


        }
        break;
    }

    return FALSE;
}
