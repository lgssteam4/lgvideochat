#include "Update.h"

extern std::string accessToken;
std::string newEmail = "";
bool checkDuplicateEmail = false;

bool updatePasswordEmail(const std::string& password, const std::string& newPassword,
    const std::string& confirmPassword, const std::string& email, const std::string& otp) {

    unsigned int rc = 0;
    std::string data;
    std::string api = "/api/user/update/";
    std::string sessionToken = accessToken;

    // Append current password
    if (!password.empty()) {
        data += "current_password=" + password + "&";
    }

    // Append new password and confirmation password
    if (!newPassword.empty() && !confirmPassword.empty()) {
        data += "new_password=" + newPassword + "&";
        data += "confirm_new_password=" + confirmPassword + "&";
    }

    // Append new email
    if (!email.empty()) {
        data += "new_email=" + email + "&";
    }

    // Append otp
    data += "otp=" + otp;

    rc = sendPostRequest(api, data, sessionToken);
    if (rc == 200) {
        return true;
    }

    return false;
}

// OTP 버튼 상태를 나타내는 변수
bool updateOTPEnabled = true;

// 카운트다운을 표시하는 함수
void showCountdown(HWND hDlg)
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
        SetDlgItemTextW(hDlg, IDC_UPDATE_T_OTP_TIME, countdownText.c_str());

        // 1초 대기
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // 카운트다운 감소
        countdownSeconds--;
    }

    // 카운트다운이 종료되면 OTP 버튼을 다시 활성화
    updateOTPEnabled = true;
    EnableWindow(GetDlgItem(hDlg, IDC_UPDATE_BUTTON_OTP), TRUE);

    // IDC_LOGIN_E_OTP Edit 창의 핸들을 가져옴
    HWND hEditOTP = GetDlgItem(hDlg, IDC_UPDATE_E_OTP);

    // IDC_LOGIN_E_OTP Edit 창을 활성화
    EnableWindow(hEditOTP, FALSE);

}

bool getOTP(HWND hDlg)
{
    unsigned int rc = 0;

    std::string api = "/api/user/generate-otp";
    std::string sessionToken = accessToken;
    
    rc = sendGetRequest(api, sessionToken);
    if (rc == 200) {
        // 업데이트가 성공하면 알림 창을 띄웁니다.
        MessageBox(hDlg, TEXT("Please enter the OTP code that has been sent to your email"), TEXT("Get OTP"), MB_OK | MB_ICONINFORMATION);
    }
    else {
        return false;
    }

    // OTP 버튼을 비활성화
    updateOTPEnabled = false;
    EnableWindow(GetDlgItem(hDlg, IDC_UPDATE_BUTTON_OTP), FALSE);

    // IDC_LOGIN_E_OTP Edit 창의 핸들을 가져옴
    HWND hEditOTP = GetDlgItem(hDlg, IDC_UPDATE_E_OTP);

    // IDC_LOGIN_E_OTP Edit 창을 활성화
    EnableWindow(hEditOTP, TRUE);

    // 카운트다운 시작
    std::thread countdownThread(showCountdown, hDlg);
    countdownThread.detach();

    return true;
}

// Function to perform update logic
bool performUpdate(HWND hDlg)
{
    bool changePassword = false;
    bool changePEmail = false;

    // Get password text
    std::string password;
    if (!getControlText(hDlg, IDC_UPDATE_E_PW, password))
    {
        BOOST_LOG_TRIVIAL(error) << "Password is empty";
        MessageBox(hDlg, TEXT("Please enter your current password"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    else if (!validatePassword(password)) {
        BOOST_LOG_TRIVIAL(error) << "password is invalid";
        MessageBox(hDlg, TEXT("Password is invalid"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    // Get new password text
    std::string newPassword;
    bool isPasswordEntered = getControlText(hDlg, IDC_UPDATE_E_NEW_PW, newPassword);

    // Get confirmation password text
    std::string confirmPassword;
    bool isConfirmPasswordEntered = getControlText(hDlg, IDC_UPDATE_E_NEW_PW2, confirmPassword);

    if (isPasswordEntered ^ isConfirmPasswordEntered)
    {
        MessageBox(hDlg, TEXT("Please enter both new password and confirmation password"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    if (isPasswordEntered && isConfirmPasswordEntered)
    {
        if (!validatePassword(newPassword)) {
            MessageBox(hDlg, TEXT("New password is invalid"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
            return false;
        }
        if (!validatePassword(confirmPassword)) {
            MessageBox(hDlg, TEXT("Confirmation password is invalid"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
            return false;
        }
        if (newPassword != confirmPassword)
        {
            BOOST_LOG_TRIVIAL(error) << "Password and confirmation password do not match";
            MessageBox(hDlg, TEXT("New password and confirmation password do not match"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
            return false;
        }
        changePassword = true;
    }

    // Get new email text
    std::string email;

    if (!getControlText(hDlg, IDC_UPDATE_E_NEW_EMAIL, email))
    {
        if (!changePassword)
        {
            MessageBox(hDlg, TEXT("Please enter a new password or email"), TEXT("Error"), MB_OK | MB_ICONERROR);
            return false;
        }
    }
    else
    {
        // Check if the email is a duplicate
        // Check if the email matches the newEmail
        if (!checkDuplicateEmail || (email != newEmail))
        {
            checkDuplicateEmail = false;
            newEmail = "";
            MessageBox(hDlg, TEXT("Please click the [Duplicate Check] button"), TEXT("Error"), MB_OK | MB_ICONERROR);
            return false;
        }
    }

    // Get OTP text
    std::string otp;
    if (!getControlText(hDlg, IDC_UPDATE_E_OTP, otp))
    {
        MessageBox(hDlg, TEXT("Please enter OTP"), TEXT("OTP Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    if (!updatePasswordEmail(password, newPassword, confirmPassword, email, otp))
    {
        MessageBox(hDlg, TEXT("You cannot update your password or email"), TEXT("Update Error"), MB_OK | MB_ICONERROR);
        return false;
    }


    return true;
}

// Message handler for Login box.
INT_PTR CALLBACK Update(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            // Perform update
            if (performUpdate(hDlg))
            {
                // 업데이트가 성공하면 알림 창을 띄웁니다.
                MessageBox(hDlg, TEXT("Update successful!"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);

                // 업데이트가 성공하면 다이얼로그를 닫습니다.
                EndDialog(hDlg, IDOK);
            }
            else
            {
                // 입력이 유효하지 않거나 업데이트가 실패한 경우에 대한 처리
                // MessageBox(hDlg, TEXT("Invalid email, password, or OTP."), TEXT("Update Error"), MB_OK | MB_ICONERROR);
                return FALSE;
            }

            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // 취소 버튼을 누르면 다이얼로그를 닫습니다.
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_UPDATE_BUTTON_DUPLICATE)
        {
            // IDC_UPDATE_BUTTON_DUPLICATE 버튼 클릭 시 OnButtonOTPClick 함수 호출
            std::string email;
            checkDuplicateEmail = checkEmail(hDlg, IDC_UPDATE_E_NEW_EMAIL, email);
            if (checkDuplicateEmail)
            {
                newEmail = email;
            }
            
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_UPDATE_BUTTON_OTP)
        {
            // IDC_UPDATE_BUTTON_OTP 버튼 클릭 시 getOTP 함수 호출
            getOTP(hDlg);

            return TRUE;
        }
        break;
    }

    return FALSE;
}
