#include "Login.h"
#include "BackendHttpsClient.h"
#include <string>
#include <iostream>

std::string loginToken;
std::string accessToken;

// OTP ��ư ���¸� ��Ÿ���� ����
bool otpButtonEnabled = true;

// ī��Ʈ�ٿ��� ǥ���ϴ� �Լ�
void ShowCountdown(HWND hDlg)
{
    // 1���� ��Ÿ���� ��
    int countdownSeconds = 1 * 60;

    while (countdownSeconds >= 0)
    {
        // �а� �� ���
        int minutes = countdownSeconds / 60;
        int seconds = countdownSeconds % 60;

        // �ؽ�Ʈ ���ڿ� ī��Ʈ�ٿ� ǥ��
        std::wstring countdownText = std::to_wstring(minutes / 10) + std::to_wstring(minutes % 10) + L":" +
            std::to_wstring(seconds / 10) + std::to_wstring(seconds % 10);
        SetDlgItemTextW(hDlg, IDC_LOGIN_T_TIME, countdownText.c_str());

        // 1�� ���
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // ī��Ʈ�ٿ� ����
        countdownSeconds--;
    }

    // ī��Ʈ�ٿ��� ����Ǹ� OTP ��ư�� �ٽ� Ȱ��ȭ
    otpButtonEnabled = true;
    EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), TRUE);

}
// OTP ���� �� ���� �߼� �Լ�, �̻��. �������� ����.
void GenerateAndSendOTP(HWND hDlg)
{
    // 6�ڸ� OTP ����
    srand(static_cast<unsigned int>(time(nullptr)));
    int otp = rand() % 900000 + 100000;

    // OTP�� ���ڿ��� ��ȯ
    generatedOTP = std::to_string(otp);

    // �̸��� �߼� �ڵ� �ۼ�
    // ...

    // �߼� �Ϸ� �޽��� �ڽ�
    std::wstring message = L"OTP generated: " + std::wstring(generatedOTP.begin(), generatedOTP.end());
    MessageBoxW(hDlg, message.c_str(), L"OTP Generated", MB_OK | MB_ICONINFORMATION);

}

void OnButtonOTPClick(HWND hDlg)
{
    // IDC_LOGIN_E_OTP Edit â�� �ڵ��� ������
    HWND hEditOTP = GetDlgItem(hDlg, IDC_LOGIN_E_OTP);

    // IDC_LOGIN_E_OTP Edit â�� Ȱ��ȭ
    EnableWindow(hEditOTP, TRUE);
}

// Function to perform login logic
bool PerformLogin(HWND hDlg)
{
    int rc = 0;
    unsigned int status_code;
    std::map<std::string, std::string> response;
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
    std::string input_otp;
    if (otpLength > 0)
    {
        std::vector<char> buffer(otpLength + 1);
        GetWindowTextA(hOTPEdit, buffer.data(), otpLength + 1);
        input_otp = buffer.data();
    }

    std::cout << "test_sch, login_token: " << loginToken << std::endl;
    std::cout << "test_sch, input_otp: " << input_otp << std::endl;

    // Perform login logic with email, password, and OTP. ������ ����
    if (!email.empty() && !password.empty() && !input_otp.empty())
    {
        // Check if the entered email, password, and OTP match the predefined values and generated OTP
        std::string data = "otp=" + input_otp + "&" + "login_token=" + loginToken;
        std::cout << "test_sch, data: " << data << std::endl;

        rc = request("POST", "/api/auth/verify-otp/", data, "", &status_code, response);
        if (status_code == 200)
        {
            // �α����� �����ϸ� true�� ��ȯ�մϴ�.
            accessToken = response["access_token"];
            accessToken = accessToken.substr(1, loginToken.length() - 2);
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

    // �Է��� ��ȿ���� �ʰų� �α����� ������ ��쿡�� false�� ��ȯ�մϴ�.
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
                // �α����� �����ϸ� �˸� â�� ���ϴ�.
                MessageBox(hDlg, TEXT("Login successful!"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);

                // �α����� �����ϸ� ���̾�α׸� �ݽ��ϴ�.
                EndDialog(hDlg, IDOK);
            }
            else
            {
                // �Է��� ��ȿ���� �ʰų� �α����� ������ ��쿡 ���� ó��
                MessageBox(hDlg, TEXT("Invalid email, password, or OTP."), TEXT("Login Error"), MB_OK | MB_ICONERROR);
            }

            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // ��� ��ư�� ������ ���̾�α׸� �ݽ��ϴ�.
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_BUTTON_OTP) // e-mail, pw �Է� �� otp ������ư click
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

            // IDC_BUTTON_OTP ��ư�� ������ OTP�� �����ϰ� ���Ϸ� �߼��մϴ�.
            std::string data = "email=" + email + "&" + "password=" + password;

			rc = request("POST", "/api/auth/login/", data, "", &status_code, response);
            if(status_code == 200)
            {
                loginToken = response["login_token"];
                loginToken = loginToken.substr(1, loginToken.length() - 2);
                std::cout << "********** test_sch, loginToken: " << loginToken << std::endl;

                // IDC_BUTTON_OTP ��ư Ŭ�� �� OnButtonOTPClick �Լ� ȣ��
                OnButtonOTPClick(hDlg);

                // OTP ��ư�� ��Ȱ��ȭ
                otpButtonEnabled = false;
                EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), FALSE);

                // ī��Ʈ�ٿ� ����
                std::thread countdownThread(ShowCountdown, hDlg);
                countdownThread.detach();
                return TRUE;
            
            }
            else
            {
                std::cout << " email & pw not matched" << std::endl;
                return FALSE; // email & pw not matched.
            }


        }
        break;
    }

    return FALSE;
}
