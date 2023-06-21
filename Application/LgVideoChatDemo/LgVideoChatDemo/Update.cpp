#include "Update.h"

extern std::string loginToken;
extern std::string accessToken;
std::string newEmail = "";
bool checkDuplicateEmail = false;

// The GetEditText function retrieves the text from a specified window control
std::string GetEditText(HWND hEdit)
{
    int length = GetWindowTextLength(hEdit);
    if (length > 0)
    {
        std::vector<char> buffer(length + 1);
        GetWindowTextA(hEdit, buffer.data(), length + 1);
        return buffer.data();
    }
    return "";
}

// The getControlText function retrieves the text from a specified window control.
bool getControlText(HWND hDlg, int controlID, std::string& text)
{
    HWND hControl = GetDlgItem(hDlg, controlID);
    text = GetEditText(hControl);

    if (text.empty())
    {
        return false;
    }

    return true;
}

// Function to check if the given email is valid
bool isValidEmail(const std::string& email) {
    // Regular expression pattern for email validation
    const std::regex pattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return std::regex_match(email, pattern);
}

// Function to check if the given email is a duplicate
bool isDuplicateEmail(const std::string& email) {
    checkDuplicateEmail = false;
    unsigned int rc = 0;

    std::string api = "/api/check-email/";
    std::string data = "email=" + email;
    rc = sendPostRequest(api, data, "");
    if (rc == 403 || rc == 400) {
        return true;
    }
    return false;
}

bool updatePasswordEmail(const std::string& password, const std::string& newPassword,
    const std::string& confirmPassword, const std::string& email, const std::string& otp) {

    unsigned int rc = 0;
    std::string data;
    std::string api = "/api/user/update/";
    std::string sessionToken = loginToken;

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

// Function to perform email validation and duplicate check
bool checkEmail(HWND hDlg) {
    // Get new email text
    std::string email;

    if (!getControlText(hDlg, IDC_UPDATE_E_NEW_EMAIL, email))
    {
        MessageBox(hDlg, TEXT("Please enter new email"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    if (!isValidEmail(email)) {
        MessageBox(hDlg, TEXT("Invalid email format"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    if (isDuplicateEmail(email)) {
        MessageBox(hDlg, TEXT("This email is unavailable (Duplicate)"), TEXT("Email Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    else {
        newEmail = email;
        checkDuplicateEmail = true;
        MessageBox(hDlg, TEXT("This email is available"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);
    }

    return true;
}

// OTP ��ư ���¸� ��Ÿ���� ����
bool updateOTPEnabled = true;

// ī��Ʈ�ٿ��� ǥ���ϴ� �Լ�
void showCountdown(HWND hDlg)
{
    // 1���� ��Ÿ���� ��
    int countdownSeconds = 3 * 60;

    while (countdownSeconds >= 0)
    {
        // �а� �� ���
        int minutes = countdownSeconds / 60;
        int seconds = countdownSeconds % 60;

        // �ؽ�Ʈ ���ڿ� ī��Ʈ�ٿ� ǥ��
        std::wstring countdownText = std::to_wstring(minutes / 10) + std::to_wstring(minutes % 10) + L":" +
            std::to_wstring(seconds / 10) + std::to_wstring(seconds % 10);
        SetDlgItemTextW(hDlg, IDC_UPDATE_T_OTP_TIME, countdownText.c_str());

        // 1�� ���
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // ī��Ʈ�ٿ� ����
        countdownSeconds--;
    }

    // ī��Ʈ�ٿ��� ����Ǹ� OTP ��ư�� �ٽ� Ȱ��ȭ
    updateOTPEnabled = true;
    EnableWindow(GetDlgItem(hDlg, IDC_UPDATE_BUTTON_OTP), TRUE);

    // IDC_LOGIN_E_OTP Edit â�� �ڵ��� ������
    HWND hEditOTP = GetDlgItem(hDlg, IDC_UPDATE_E_OTP);

    // IDC_LOGIN_E_OTP Edit â�� Ȱ��ȭ
    EnableWindow(hEditOTP, FALSE);

}

bool getOTP(HWND hDlg)
{
    unsigned int rc = 0;

    std::string api = "/api/user/generate-otp";
    std::string sessionToken = loginToken;
    
    rc = sendGetRequest(api, sessionToken);
    if (rc == 200) {
        // ������Ʈ�� �����ϸ� �˸� â�� ���ϴ�.
        MessageBox(hDlg, TEXT("Please enter the OTP code that has been sent to your email"), TEXT("Get OTP"), MB_OK | MB_ICONINFORMATION);
    }
    else {
        return false;
    }

    // OTP ��ư�� ��Ȱ��ȭ
    updateOTPEnabled = false;
    EnableWindow(GetDlgItem(hDlg, IDC_UPDATE_BUTTON_OTP), FALSE);

    // IDC_LOGIN_E_OTP Edit â�� �ڵ��� ������
    HWND hEditOTP = GetDlgItem(hDlg, IDC_UPDATE_E_OTP);

    // IDC_LOGIN_E_OTP Edit â�� Ȱ��ȭ
    EnableWindow(hEditOTP, TRUE);

    // ī��Ʈ�ٿ� ����
    std::thread countdownThread(showCountdown, hDlg);
    countdownThread.detach();

    return true;
}

bool validatePassword(const std::string& password)
{
    // Check if password length is at least 10 characters
    if (password.length() < 10) {
        return false;
    }

    // Check if password contains at least one digit
    if (!std::regex_search(password, std::regex("\\d"))) {
        return false;
    }

    // Check if password contains at least one special character
    if (!std::regex_search(password, std::regex("[!@#$%^&*(),.?\":{}|<>]"))) {
        return false;
    }

    // Password passed all validation checks
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
        MessageBox(hDlg, TEXT("Please enter your current password"), TEXT("Password Error"), MB_OK | MB_ICONERROR);
        return false;
    }
    else if (!validatePassword(password)) {
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
            MessageBox(hDlg, TEXT("Please click the [Duplicate Email] button"), TEXT("Error"), MB_OK | MB_ICONERROR);
            return false;
        }
    }

    // Get otp
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

    /*
    if (!newPassword.empty() && email.empty())
    {
        // Update password only
    }
    else if (newPassword.empty() && !email.empty())
    {
        // Update email only
    }
    else if (!newPassword.empty() && !email.empty())
    {
        // Update password & email
    }
    */

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
                // ������Ʈ�� �����ϸ� �˸� â�� ���ϴ�.
                MessageBox(hDlg, TEXT("Update successful!"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);

                // ������Ʈ�� �����ϸ� ���̾�α׸� �ݽ��ϴ�.
                EndDialog(hDlg, IDOK);
            }
            else
            {
                // �Է��� ��ȿ���� �ʰų� ������Ʈ�� ������ ��쿡 ���� ó��
                // MessageBox(hDlg, TEXT("Invalid email, password, or OTP."), TEXT("Update Error"), MB_OK | MB_ICONERROR);
                return FALSE;
            }

            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // ��� ��ư�� ������ ���̾�α׸� �ݽ��ϴ�.
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_UPDATE_BUTTON_DUPLICATE)
        {
            // IDC_UPDATE_BUTTON_DUPLICATE ��ư Ŭ�� �� OnButtonOTPClick �Լ� ȣ��
            checkEmail(hDlg);

            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_UPDATE_BUTTON_OTP)
        {
            // IDC_UPDATE_BUTTON_OTP ��ư Ŭ�� �� getOTP �Լ� ȣ��
            getOTP(hDlg);

            return TRUE;
        }
        break;
    }

    return FALSE;
}
