#include "Update.h"

std::string currentPassword = "test1234";

// Function to perform update logic
bool PerformUpdate(HWND hDlg)
{
    // Get password text
    HWND hPasswordEdit = GetDlgItem(hDlg, IDC_UPDATE_E_PW);
    int passwordLength = GetWindowTextLength(hPasswordEdit);
    std::string password;
    if (passwordLength > 0)
    {
        std::vector<char> buffer(passwordLength + 1);
        GetWindowTextA(hPasswordEdit, buffer.data(), passwordLength + 1);
        password = buffer.data();
    }

    // Compare the entered password with loginPassword
    if (password == currentPassword)
    {
        // Get new password text
        HWND hNewPasswordEdit = GetDlgItem(hDlg, IDC_UPDATE_E_NEW_PW);
        int newPasswordLength = GetWindowTextLength(hNewPasswordEdit);
        std::string newPassword;
        if (newPasswordLength > 0)
        {
            std::vector<char> buffer(newPasswordLength + 1);
            GetWindowTextA(hNewPasswordEdit, buffer.data(), newPasswordLength + 1);
            newPassword = buffer.data();
        }

        // Get confirmation password text
        HWND hConfirmPasswordEdit = GetDlgItem(hDlg, IDC_UPDATE_E_NEW_PW2);
        int confirmPasswordLength = GetWindowTextLength(hConfirmPasswordEdit);
        std::string confirmPassword;
        if (confirmPasswordLength > 0)
        {
            std::vector<char> buffer(confirmPasswordLength + 1);
            GetWindowTextA(hConfirmPasswordEdit, buffer.data(), confirmPasswordLength + 1);
            confirmPassword = buffer.data();
        }

        // Check if the new password and confirmation password match
        if (newPassword == confirmPassword)
        {
            // Return true if the passwords match
            return true;
        }
    }

    // Return false if the entered password doesn't match or the new passwords don't match
    return false;
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
            if (PerformUpdate(hDlg))
            {
                // 업데이트가 성공하면 알림 창을 띄웁니다.
                MessageBox(hDlg, TEXT("Update successful!"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);

                // 업데이트가 성공하면 다이얼로그를 닫습니다.
                EndDialog(hDlg, IDOK);
            }
            else
            {
                // 입력이 유효하지 않거나 업데이트가 실패한 경우에 대한 처리
                MessageBox(hDlg, TEXT("Invalid email, password, or OTP."), TEXT("Update Error"), MB_OK | MB_ICONERROR);
            }

            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // 취소 버튼을 누르면 다이얼로그를 닫습니다.
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }

    return FALSE;
}
