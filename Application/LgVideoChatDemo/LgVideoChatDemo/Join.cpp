#include "Join.h"

// Message handler for Join box.
INT_PTR CALLBACK Join(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            // ��� ��ư�� ������ ���̾�α׸� �ݽ��ϴ�.
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        else if (LOWORD(wParam) == IDC_JOIN_CHECKEMAIL)
        {

        }
        break;
    }

    return FALSE;
}