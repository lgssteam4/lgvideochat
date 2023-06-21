#include "Login.h"

std::string loginToken;
std::string accessToken;

// OTP ��ư ���¸� ��Ÿ���� ����
bool otpButtonEnabled = true;

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
    std::string email;
    if (!getEmailText(hDlg, IDC_LOGIN_E_EMAIL, email)) return false;

    // Get password text
    std::string password;
    if (!getPasswordText(hDlg, IDC_LOGIN_E_PASSWORD, password)) return false;

    // Get OTP text
    std::string input_otp;
    if (!getControlText(hDlg, IDC_LOGIN_E_OTP, input_otp))
    {
        MessageBox(hDlg, TEXT("Please enter OTP"), TEXT("OTP Error"), MB_OK | MB_ICONERROR);
        return false;
    }

    std::cout << "test_sch, login_token: " << loginToken << std::endl;
    std::cout << "test_sch, input_otp: " << input_otp << std::endl;

    // Perform login logic with email, password, and OTP. ������ ����
   
    // Check if the entered email, password, and OTP match the predefined values and generated OTP
    std::string data = "otp=" + input_otp + "&" + "login_token=" + loginToken;
    std::cout << "test_sch, data: " << data << std::endl;

    rc = request("POST", "/api/auth/verify-otp/", data, "", &status_code, response);
    if (status_code == 200)
    {
        // �α����� �����ϸ� true�� ��ȯ�մϴ�.
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
                MessageBox(hDlg, TEXT("Login successful!"), TEXT("Success"), MB_OK | MB_ICONINFORMATION);
                EndDialog(hDlg, IDOK);
            }
            else
            {
                MessageBox(hDlg, TEXT("Invalid email, password, or OTP."), TEXT("Login Error"), MB_OK | MB_ICONERROR);
            }

            return TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_BUTTON_OTP)
        {
            int rc = 0;
            unsigned int status_code;
            std::map<std::string, std::string> response;
            // Send GET request
            rc = request("GET", "/", "","",&status_code,response);

            // Get email text
            std::string email;
            if (!getEmailText(hDlg, IDC_LOGIN_E_EMAIL, email)) return FALSE;

            // Get password text
            std::string password;
            if (!getPasswordText(hDlg, IDC_LOGIN_E_PASSWORD, password)) return FALSE;

            // IDC_BUTTON_OTP ��ư�� ������ OTP�� �����ϰ� ���Ϸ� �߼��մϴ�.
            std::string data = "email=" + email + "&" + "password=" + password;

			rc = request("POST", "/api/auth/login/", data, "", &status_code, response);
            if(status_code == 200)
            {
                loginToken = response["login_token"];
                std::cout << "********** test_sch, loginToken: " << loginToken << std::endl;

                // IDC_BUTTON_OTP ��ư Ŭ�� �� OnButtonOTPClick �Լ� ȣ��
                OnButtonOTPClick(hDlg);

                // OTP ��ư�� ��Ȱ��ȭ
                otpButtonEnabled = false;
                EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), FALSE);

                // ī��Ʈ�ٿ� ����
                std::thread countdownThread(ShowCountdown, hDlg, IDC_LOGIN_T_TIME);
                countdownThread.detach();

                otpButtonEnabled = true;
                EnableWindow(GetDlgItem(hDlg, IDC_BUTTON_OTP), TRUE);

                return TRUE;
            }
            else if (status_code == 403)
            {
                std::cout << "Please proceed with email account activation" << std::endl;
                MessageBox(hDlg, TEXT("Please proceed with email account activation"), TEXT("Account Error"), MB_OK | MB_ICONERROR);
                return FALSE;
            }
            else
            {
                std::cout << "Email & Password not matched" << std::endl;
                MessageBox(hDlg, TEXT("Email & Password not matched"), TEXT("Account Error"), MB_OK | MB_ICONERROR);
                return FALSE;
            }


        }
        break;
    }

    return FALSE;
}
