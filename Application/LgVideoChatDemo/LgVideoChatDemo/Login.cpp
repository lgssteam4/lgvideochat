#include "Login.h"

std::string loginEmail = "test@gmail.com";
std::string loginPassword = "test1234";
std::string generatedOTP;

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
// OTP 생성 및 메일 발송 함수
void GenerateAndSendOTP(HWND hDlg)
{
    // 6자리 OTP 생성
    srand(static_cast<unsigned int>(time(nullptr)));
    int otp = rand() % 900000 + 100000;

    // OTP를 문자열로 변환
    generatedOTP = std::to_string(otp);

    // 이메일 발송 코드 작성
    // ...

    // 발송 완료 메시지 박스
    std::wstring message = L"OTP generated: " + std::wstring(generatedOTP.begin(), generatedOTP.end());
    MessageBoxW(hDlg, message.c_str(), L"OTP Generated", MB_OK | MB_ICONINFORMATION);

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

    // Get OTP text
    HWND hOTPEdit = GetDlgItem(hDlg, IDC_LOGIN_E_OTP);
    int otpLength = GetWindowTextLength(hOTPEdit);
    std::string otp;
    if (otpLength > 0)
    {
        std::vector<char> buffer(otpLength + 1);
        GetWindowTextA(hOTPEdit, buffer.data(), otpLength + 1);
        otp = buffer.data();
    }

    // Perform login logic with email, password, and OTP
    if (!email.empty() && !password.empty() && !otp.empty())
    {
        // Check if the entered email, password, and OTP match the predefined values and generated OTP
        if (email == loginEmail && password == loginPassword && otp == generatedOTP)
        {
            // 로그인이 성공하면 true를 반환합니다.
            return true;
        }
    }

    // 입력이 유효하지 않거나 로그인이 실패한 경우에는 false를 반환합니다.
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
        else if (LOWORD(wParam) == IDC_BUTTON_OTP)
        {
            // IDC_BUTTON_OTP 버튼 클릭 시 OnButtonOTPClick 함수 호출
            OnButtonOTPClick(hDlg);

            // IDC_BUTTON_OTP 버튼을 누르면 OTP를 생성하고 메일로 발송합니다.
            GenerateAndSendOTP(hDlg);

            // OTP 버튼을 비활성화
            otpButtonEnabled = false;
            EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), FALSE);

            // 카운트다운 시작
            std::thread countdownThread(ShowCountdown, hDlg);
            countdownThread.detach();
            return TRUE;
        }
        break;
    }

    return FALSE;
}

/*
// Message handler for Login box.
INT_PTR CALLBACK Login(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
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
}*/