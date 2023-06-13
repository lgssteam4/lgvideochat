#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include < iostream >
#include <new>
#include "VideoServer.h"
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"
#include "Camera.h"
#include "ApplyOpenSSL.h"

static  std::vector<uchar> sendbuff;//buffer for coding
enum InputMode { ImageSize, Image };
static HANDLE hAcceptEvent = INVALID_HANDLE_VALUE;
static HANDLE hListenEvent = INVALID_HANDLE_VALUE;
static HANDLE hEndVideoServerEvent = INVALID_HANDLE_VALUE;
static HANDLE hTimer = INVALID_HANDLE_VALUE;
static SOCKET Listen = INVALID_SOCKET;
static SOCKET Accept = INVALID_SOCKET;
static SSL* sslSocketForServer;
static cv::Mat ImageIn;
static DWORD ThreadVideoServerID;
static HANDLE hThreadVideoServer = INVALID_HANDLE_VALUE;
static int NumEvents;
static unsigned int InputBytesNeeded;
static char* InputBuffer = NULL;
static char* InputBufferWithOffset = NULL;
static InputMode Mode = ImageSize;
static bool RealConnectionActive = false;

static void VideoServerSetExitEvent(void);
static void VideoServerCleanup(void);
static DWORD WINAPI ThreadVideoServer(LPVOID ivalue);
static void CleanUpClosedConnection(void);

bool StartVideoServer(bool& Loopback)
{
	if (hThreadVideoServer == INVALID_HANDLE_VALUE)
	{
		hThreadVideoServer = CreateThread(NULL, 0, ThreadVideoServer, &Loopback, 0, &ThreadVideoServerID);
	}
	return true;
}
bool StopVideoServer(void)
{
	VideoServerSetExitEvent();
	if (hThreadVideoServer != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(hThreadVideoServer, INFINITE);
		hThreadVideoServer = INVALID_HANDLE_VALUE;
	}
	VideoServerCleanup();
	return true;
}
bool IsVideoServerRunning(void)
{
	if (hThreadVideoServer == INVALID_HANDLE_VALUE) return false;
	else return true;

}
static void VideoServerSetExitEvent(void)
{
	if (hEndVideoServerEvent != INVALID_HANDLE_VALUE)
		SetEvent(hEndVideoServerEvent);
}
static void VideoServerCleanup(void)
{
	if (hListenEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hListenEvent);
		hListenEvent = INVALID_HANDLE_VALUE;
	}
	if (hAcceptEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hAcceptEvent);
		hAcceptEvent = INVALID_HANDLE_VALUE;
	}
	if (hEndVideoServerEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hEndVideoServerEvent);
		hEndVideoServerEvent = INVALID_HANDLE_VALUE;
	}
	if (hTimer != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hTimer);
		hTimer = INVALID_HANDLE_VALUE;
	}

	if (Listen != INVALID_SOCKET)
	{
		closesocket(Listen);
		Listen = INVALID_SOCKET;
	}
	if (Accept != INVALID_SOCKET)
	{
		closesocket(Accept);
		Accept = INVALID_SOCKET;
	}
}

static DWORD WINAPI ThreadVideoServer(LPVOID ivalue)
{
	SOCKADDR_IN InternetAddr;
	HANDLE ghEvents[4];
	DWORD dwEvent;
	bool  Loopback = *((bool*)ivalue);
	bool  LoopbackOverRide = false;
	unsigned int SizeofImage;
	unsigned int CurrentInputBufferSize = 1024 * 10;

	std::cout << "Video Server Started Loopback " << (Loopback ? "True" : "False") << std::endl;

	RealConnectionActive = false;
	Mode = ImageSize;
	InputBytesNeeded = sizeof(unsigned int);
	InputBuffer = (char*)std::realloc(NULL, CurrentInputBufferSize);
	InputBufferWithOffset = InputBuffer;

	if (InputBuffer == NULL)
	{
		std::cout << "InputBuffer Realloc failed" << std::endl;
		return 1;
	}

	// SSL 컨텍스트 생성 및 초기화
	SSL_CTX* ctxForServer = createSSLContextForServer();

	// 서버가 클라이언트의 연결을 수락하기 위해 사용될 소켓 생성
	if ((Listen = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		std::cout << "socket() failed with error " << WSAGetLastError() << std::endl;
		return 1;
	}

	// SSL 소켓 생성
	sslSocketForServer = createSSLSocket(ctxForServer, Listen);

	// 클라이언트의 연결 요청 및 소켓 이벤트 처리 핸들
	hListenEvent = WSACreateEvent();

	// 비디오 서버 종료 이벤트 핸들
	hEndVideoServerEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// 소켓과 이벤트 핸들을 연결 (FD_ACCEPT와 FD_CLOSE 이벤트 감시하도록 지정)
	// FD_ACCEPT : 클라이언트의 연결 요청을 수락할 때 발생하는 이벤트
	// FD_CLOSE : 클라이언트와의 연결이 종료될 때 발생하는 이벤트
	if (WSAEventSelect(SSL_get_fd(sslSocketForServer), hListenEvent, FD_ACCEPT | FD_CLOSE) == SOCKET_ERROR)
	{
		std::cout << "WSAEventSelect() failed with error " << WSAGetLastError() << std::endl;
		return 1;
	}
	InternetAddr.sin_family = AF_INET;
	InternetAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	InternetAddr.sin_port = htons(VIDEO_PORT);

	// 소켓에 IP 주소와 포트 번호를 바인딩
	if (bind(SSL_get_fd(sslSocketForServer), (PSOCKADDR)&InternetAddr, sizeof(InternetAddr)) == SOCKET_ERROR)
	{
		std::cout << "bind() failed with error " << WSAGetLastError() << std::endl;
		return 1;
	}

	// 클라이언트의 연결을 수신하기 위해 소켓을 대기 상태로 설정
	if (listen(SSL_get_fd(sslSocketForServer), 5))
	{
		std::cout << "listen() failed with error " << WSAGetLastError() << std::endl;
		return 1;
	}

	ghEvents[0] = hEndVideoServerEvent;
	ghEvents[1] = hListenEvent;
	NumEvents = 2;
	while (1) {
		dwEvent = WaitForMultipleObjects(
			NumEvents,	// number of objects in array
			ghEvents,	// array of objects
			FALSE,		// wait for any object
			INFINITE);	// INFINITE) wait

		// 비디오 서버 종료 이벤트
		if (dwEvent == WAIT_OBJECT_0) break;
		// 클라이언트의 연결 요청 이벤트
		else if (dwEvent == WAIT_OBJECT_0 + 1)
		{
			WSANETWORKEVENTS NetworkEvents;
			// Listen 소켓의 네트워크 이벤트를 가져옴
			if (SOCKET_ERROR == WSAEnumNetworkEvents(Listen, hListenEvent, &NetworkEvents))
			{
				std::cout << "WSAEnumNetworkEvent: " << WSAGetLastError() << " dwEvent  " << dwEvent << " lNetworkEvent " << std::hex << NetworkEvents.lNetworkEvents << std::endl;
				NetworkEvents.lNetworkEvents = 0;
			}
			else
			{
				// FD_ACCEPT 이벤트가 발생한 경우, 새로운 클라이언트 연결을 수락
				if (NetworkEvents.lNetworkEvents & FD_ACCEPT)
				{
					if (NetworkEvents.iErrorCode[FD_ACCEPT_BIT] != 0)
					{
						std::cout << "FD_ACCEPT failed with error " << NetworkEvents.iErrorCode[FD_ACCEPT_BIT] << std::endl;
					}
					else
					{
						if (Accept == INVALID_SOCKET)
						{
							struct sockaddr_storage sa;
							socklen_t sa_len = sizeof(sa);
							char RemoteIp[INET6_ADDRSTRLEN];

							LARGE_INTEGER liDueTime;

							// Accept a new connection, and add it to the socket and event lists
							Accept = accept(Listen, (struct sockaddr*)&sa, &sa_len);

							int err = getnameinfo((struct sockaddr*)&sa, sa_len, RemoteIp, sizeof(RemoteIp), 0, 0, NI_NUMERICHOST);
							if (err != 0) {
								snprintf(RemoteIp, sizeof(RemoteIp), "invalid address");
							}
							else
							{
								std::cout << "Accepted Connection " << RemoteIp << std::endl;
							}
							if (!Loopback)
							{
								if ((strcmp(RemoteIp, LocalIpAddress) == 0) ||
									(strcmp(RemoteIp, "127.0.0.1") == 0))
								{
									LoopbackOverRide = true;
									std::cout << "Loopback Over Ride" << std::endl;
								}
								else LoopbackOverRide = false;
							}

							// 연결 상태를 알리는 메시지 전송
							PostMessage(hWndMain, WM_REMOTE_CONNECT, 0, 0);
							hAcceptEvent = WSACreateEvent();
							WSAEventSelect(Accept, hAcceptEvent, FD_READ | FD_WRITE | FD_CLOSE);
							ghEvents[2] = hAcceptEvent;
							if ((Loopback) || (LoopbackOverRide))  NumEvents = 3;
							else
							{
								liDueTime.QuadPart = 0LL;
								if (!OpenCamera())
								{
									std::cout << "OpenCamera() Failed" << std::endl;
									break;
								}
								VoipVoiceStart(RemoteIp, VOIP_LOCAL_PORT, VOIP_REMOTE_PORT, VoipAttr);
								std::cout << "Voip Voice Started.." << std::endl;
								RealConnectionActive = true;
								hTimer = CreateWaitableTimer(NULL, FALSE, NULL);

								if (NULL == hTimer)
								{
									std::cout << "CreateWaitableTimer failed " << GetLastError() << std::endl;
									break;
								}

								if (!SetWaitableTimer(hTimer, &liDueTime, VIDEO_FRAME_DELAY, NULL, NULL, 0))
								{
									std::cout << "SetWaitableTimer failed  " << GetLastError() << std::endl;
									break;
								}
								ghEvents[3] = hTimer;
								NumEvents = 4;
							}
						}
						else
						{
							SOCKET Temp = accept(Listen, NULL, NULL);
							if (Temp != INVALID_SOCKET)
							{
								closesocket(Temp);
								std::cout << "Refused-Already Connected" << std::endl;
							}

						}
					}

				}
				// FD_CLOSE 이벤트가 발생한 경우, 해당 소켓을 닫고 정리
				if (NetworkEvents.lNetworkEvents & FD_CLOSE)
				{
					if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)
					{
						std::cout << "FD_CLOSE failed with error on Listen Socket" << NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
					}

					closesocket(Listen);
					Listen = INVALID_SOCKET;
				}
			}
		}
		// 연결된 클라이언트 소켓의 이벤트가 발생한 경우, 데이터 송수신을 처리
		else if (dwEvent == WAIT_OBJECT_0 + 2)
		{
			WSANETWORKEVENTS NetworkEvents;
			if (SOCKET_ERROR == WSAEnumNetworkEvents(Accept, hAcceptEvent, &NetworkEvents))
			{
				std::cout << "WSAEnumNetworkEvent: " << WSAGetLastError() << " dwEvent  " << dwEvent << " lNetworkEvent " << std::hex << NetworkEvents.lNetworkEvents << std::endl;
				NetworkEvents.lNetworkEvents = 0;
			}
			else
			{
				// FD_READ 이벤트가 발생한 경우, 데이터를 읽어옴
				if (NetworkEvents.lNetworkEvents & FD_READ)
				{
					if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
					{
						std::cout << "FD_READ failed with error " << NetworkEvents.iErrorCode[FD_READ_BIT] << std::endl;
					}
					// 루프백 연결인 경우, 데이터를 받아서 다시 송신
					else if ((Loopback) || (LoopbackOverRide))
					{
						unsigned char* buffer;
						u_long bytesAvailable;
						int bytestosend;
						int iResult;

						ioctlsocket(Accept, FIONREAD, &bytesAvailable);
						if (bytesAvailable >= 0)
						{
							buffer = new (std::nothrow) unsigned char[bytesAvailable];
							//std::cout << "FD_READ "<< bytesAvailable << std::endl;
							iResult = ReadDataTcpNoBlock(Accept, buffer, bytesAvailable);
							if (iResult > 0)
							{
								bytestosend = iResult;
								iResult = WriteDataTcp(Accept, buffer, bytestosend);
								delete[] buffer;
								if (iResult == SOCKET_ERROR)
								{
									std::cout << "WriteDataTcp failed: " << WSAGetLastError() << std::endl;
								}
							}
							else if (iResult == 0)
							{
								std::cout << "Connection closed on Recv" << std::endl;
								CleanUpClosedConnection();
							}
							else
							{
								std::cout << "ReadDataTcpNoBlock failed:" << WSAGetLastError() << std::endl;
							}
						}
					}
					else // No Loopback
					{
						int iResult;

						iResult = ReadDataTcpNoBlock(Accept, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
						if (iResult != SOCKET_ERROR)
						{
							if (iResult == 0)
							{
								CleanUpClosedConnection();
								std::cout << "Connection closed on Recv" << std::endl;
								break;
							}
							else
							{
								InputBytesNeeded -= iResult;
								InputBufferWithOffset += iResult;
								if (InputBytesNeeded == 0)
								{
									if (Mode == ImageSize)
									{
										Mode = Image;
										InputBufferWithOffset = InputBuffer;;
										memcpy(&SizeofImage, InputBuffer, sizeof(SizeofImage));
										SizeofImage = ntohl(SizeofImage);
										InputBytesNeeded = SizeofImage;
										if (InputBytesNeeded > CurrentInputBufferSize)
										{
											CurrentInputBufferSize = InputBytesNeeded + (10 * 1024);
											InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
											if (InputBuffer == NULL)
											{
												std::cout << "std::realloc failed " << std::endl;
											}
										}
										InputBufferWithOffset = InputBuffer;;
									}
									else if (Mode == Image)
									{
										Mode = ImageSize;
										InputBytesNeeded = sizeof(unsigned int);
										InputBufferWithOffset = InputBuffer;
										cv::imdecode(cv::Mat(SizeofImage, 1, CV_8UC1, InputBuffer), cv::IMREAD_COLOR, &ImageIn);
										DispayImage(ImageIn);
									}
								}

							}
						}
						else std::cout << "ReadDataTcpNoBlock buff failed " << WSAGetLastError() << std::endl;
					}
				}
				// FD_WRITE 이벤트가 발생한 경우, 데이터 송신할 수 있는 상태임을 의미
				if (NetworkEvents.lNetworkEvents & FD_WRITE)
				{
					if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0)
					{
						std::cout << "FD_WRITE failed with error " << NetworkEvents.iErrorCode[FD_WRITE_BIT] << std::endl;
					}
					else
					{
						std::cout << "FD_WRITE" << std::endl;
					}
				}
				// FD_CLOSE 이벤트가 발생한 경우, 해당 소켓을 닫고 정리
				if (NetworkEvents.lNetworkEvents & FD_CLOSE)
				{
					if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)
					{
						std::cout << "FD_CLOSE failed with error Connection " << NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
					}
					else
					{
						std::cout << "FD_CLOSE" << std::endl;
					}
					CleanUpClosedConnection();
				}
			}
		}
		// 타이머 이벤트가 발생한 경우, 카메라에서 프레임을 가져와 클라이언트에 전송합니다.
		else if (dwEvent == WAIT_OBJECT_0 + 3)
		{
			unsigned int numbytes;

			if (!GetCameraFrame(sendbuff))
			{
				std::cout << "Camera Frame Empty" << std::endl;
			}
			numbytes = htonl((unsigned long)sendbuff.size());
			if (WriteDataTcp(Accept, (unsigned char*)&numbytes, sizeof(numbytes)) == sizeof(numbytes))
			{
				if (WriteDataTcp(Accept, (unsigned char*)sendbuff.data(), (int)sendbuff.size()) != sendbuff.size())
				{
					std::cout << "WriteDataTcp sendbuff.data() Failed " << WSAGetLastError() << std::endl;
					CleanUpClosedConnection();
				}
			}
			else {
				std::cout << "WriteDataTcp sendbuff.size() Failed " << WSAGetLastError() << std::endl;
				CleanUpClosedConnection();
			}
		}
	}

	CleanUpClosedConnection();	// 연결이 종료된 클라이언트와 관련된 자원을 정리
	VideoServerCleanup();		// 비디오 서버 자원 정리
	std::cout << "Video Server Stopped" << std::endl;
	return 0;
}
static void CleanUpClosedConnection(void)
{
	if (Accept != INVALID_SOCKET)
	{
		closesocket(Accept);
		Accept = INVALID_SOCKET;
		PostMessage(hWndMain, WM_REMOTE_LOST, 0, 0);
	}
	if (hAcceptEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hAcceptEvent);
		hAcceptEvent = INVALID_HANDLE_VALUE;
	}
	if (hTimer != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hTimer);
		hTimer = INVALID_HANDLE_VALUE;
	}
	if (RealConnectionActive)
	{
		CloseCamera();
		VoipVoiceStop();
	}
	Mode = ImageSize;
	InputBytesNeeded = sizeof(unsigned int);
	InputBufferWithOffset = InputBuffer;
	NumEvents = 2;
	RealConnectionActive = false;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------