
/********************************************
*											*
*	RebirthGuard/splash.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"

//-----------------------------------------------------------------
//	Splash image
//-----------------------------------------------------------------
LRESULT SplashProc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	HDC hdc, memdc;
	PAINTSTRUCT ps;
	static HBITMAP hBitmap;
	switch (iMsg)
	{
	case WM_CREATE:
		hBitmap = (HBITMAP)LoadImage(myGetModuleHandle(NULL), L"splash.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
		break;
	case WM_PAINT:
		hdc = BeginPaint(hwnd, &ps);
		memdc = CreateCompatibleDC(hdc);
		SelectObject(memdc, hBitmap);
		StretchBlt(hdc, 0, 0, 200, 200, memdc, 0, 0, 200, 200, SRCCOPY);
		DeleteDC(memdc);
		EndPaint(hwnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, iMsg, wParam, lParam);
}

VOID SplashThread(VOID)
{
	HWND hwnd;
	MSG msg;
	WNDCLASS WndClass;
	WndClass.style = CS_HREDRAW | CS_VREDRAW;
	WndClass.lpfnWndProc = SplashProc;
	WndClass.cbClsExtra = 0;
	WndClass.cbWndExtra = 0;
	WndClass.hInstance = myGetModuleHandle(NULL);
	WndClass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	WndClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	WndClass.hbrBackground = (HBRUSH)CreateSolidBrush(RGB(255, 255, 255));
	WndClass.lpszMenuName = NULL;
	WndClass.lpszClassName = L"RGsplash";
	RegisterClass(&WndClass);
	RECT tray;
	GetWindowRect(FindWindow(L"Shell_TrayWnd", NULL), &tray);
	hwnd = CreateWindow(L"RGsplash", L"RGsplash", WS_POPUP | WS_EX_TOPMOST, GetSystemMetrics(SM_CXSCREEN) - 131, GetSystemMetrics(SM_CYSCREEN) - 152 - (tray.bottom - tray.top), 131, 152, NULL, NULL, WndClass.hInstance, NULL);
	UpdateWindow(hwnd);
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}