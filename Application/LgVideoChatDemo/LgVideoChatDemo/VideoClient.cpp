#include "BoostLog.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include < cstdlib >
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "VideoClient.h"
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"
#include "Camera.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"
#include "ApplyOpenSSL.h"

enum InputMode { ImageSize, Image };
static  std::vector<uchar> sendbuff;//buffer for coding
static HANDLE hClientEvent = INVALID_HANDLE_VALUE;
static HANDLE hEndVideoClientEvent = INVALID_HANDLE_VALUE;
static HANDLE hTimer = INVALID_HANDLE_VALUE;
static SOCKET Client = INVALID_SOCKET;
static SOCKET SSLClient = INVALID_SOCKET;
SSL_CTX* ctxForClient = NULL;
SSL* SSLSocketForClient = NULL;
static cv::Mat ImageIn;
static DWORD ThreadVideoClientID;
static HANDLE hThreadVideoClient = INVALID_HANDLE_VALUE;

static DWORD WINAPI ThreadVideoClient(LPVOID ivalue);
static void VideoClientSetExitEvent(void);
static void VideoClientCleanup(void);

static void VideoClientSetExitEvent(void)
{
	if (hEndVideoClientEvent != INVALID_HANDLE_VALUE)
		SetEvent(hEndVideoClientEvent);
}

static void VideoClientCleanup(void)
{
	BOOST_LOG_TRIVIAL(info) << "VideoClientCleanup";

	if (hClientEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hClientEvent);
		hClientEvent = INVALID_HANDLE_VALUE;
	}
	if (hEndVideoClientEvent != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hEndVideoClientEvent);
		hEndVideoClientEvent = INVALID_HANDLE_VALUE;
	}
	if (hTimer != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hTimer);
		hTimer = INVALID_HANDLE_VALUE;
	}
	if (Client != INVALID_SOCKET)
	{
		closesocket(Client);
		Client = INVALID_SOCKET;
		if (SSLClient != INVALID_SOCKET)
		{
			SSLClient = INVALID_SOCKET;
			SSL_free(SSLSocketForClient);
			SSL_CTX_free(ctxForClient);
		}
	}
}

bool ConnectToSever(const char* remotehostname, unsigned short remoteport)
{
	BOOST_LOG_TRIVIAL(debug) << "Client: Start ConnectToserver";

	int iResult;
	struct addrinfo   hints;
	struct addrinfo* result = NULL;
	char remoteportno[128];

	sprintf_s(remoteportno, sizeof(remoteportno), "%d", remoteport);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// 서버의 주소 정보를 가져옴
	// Get server address information
	iResult = getaddrinfo(remotehostname, remoteportno, &hints, &result);
	if (iResult != 0)
	{
		BOOST_LOG_TRIVIAL(error) << "getaddrinfo: Failed";
		return false;
	}

	if (result == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "getaddrinfo: Failed";
		return false;
	}

	// 클라이언트 소켓 생성
	// Create client socket
	if ((Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		freeaddrinfo(result);
		BOOST_LOG_TRIVIAL(error) << "video client socket() failed with error " << WSAGetLastError();
		return false;
	}
	BOOST_LOG_TRIVIAL(debug) << "Client: Success socket";

	// Connect to server.
	iResult = connect(Client, result->ai_addr, (int)result->ai_addrlen);
	freeaddrinfo(result);
	if (iResult == SOCKET_ERROR) {
		BOOST_LOG_TRIVIAL(error) << "connect function failed with error : " << WSAGetLastError();
		iResult = closesocket(Client);
		Client = INVALID_SOCKET;
		if (iResult == SOCKET_ERROR)
			BOOST_LOG_TRIVIAL(error) << "closesocket function failed with error :" << WSAGetLastError();
		return false;
	}
	BOOST_LOG_TRIVIAL(debug) << "Client: Success connect";

	// SSL 초기화
	// Initialize SSL
	initializeSSL();
	BOOST_LOG_TRIVIAL(debug) << "Client: Success initializeSSL";

	// SSL 컨텍스트 생성 및 초기화
	// Create and initialize SSL context
	ctxForClient = createSSLContextForClient();
	if (ctxForClient == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "Client: Error createSSLContextForClient";
		iResult = closesocket(Client);
		Client = INVALID_SOCKET;
		if (iResult == SOCKET_ERROR)
			BOOST_LOG_TRIVIAL(error) << "closesocket function failed with error :" << WSAGetLastError();
		return false;
	}
	BOOST_LOG_TRIVIAL(debug) << "Client: Success createSSLContextForClient";

	// SSL 소켓 생성
	// Create SSL socket
	SSLSocketForClient = SSL_new(ctxForClient);
	if (SSLSocketForClient == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "Client: Error SSL_new";
		iResult = closesocket(Client);
		Client = INVALID_SOCKET;
		SSL_CTX_free(ctxForClient);
		if (iResult == SOCKET_ERROR)
			BOOST_LOG_TRIVIAL(error) << "closesocket function failed with error :" << WSAGetLastError();
		return false;
	}
	BOOST_LOG_TRIVIAL(debug) << "Client: Success SSL_new";

	// SSL 소켓에 일반 소켓 연결
	// Connect a client socket to the SSL socket.
	int fd = SSL_set_fd(SSLSocketForClient, Client);
	if (fd != 1)
	{
		BOOST_LOG_TRIVIAL(error) << "Client: Error SSL_set_fd";
		closesocket(Client);
		Client = INVALID_SOCKET;
		SSL_free(SSLSocketForClient);
		SSL_CTX_free(ctxForClient);
		return false;
	}
	BOOST_LOG_TRIVIAL(debug) << "Client: Success SSL_set_fd";
	SSLClient = SSL_get_fd(SSLSocketForClient);

	// 인증서 검증
	// Verify certification
	//SSL_CTX_set_verify(ctxForClient, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	//BOOST_LOG_TRIVIAL(debug) << "Client: Success SSL_CTX_set_verify";

	// SSL 소켓을 사용하여 서버와 다시 연결
	// Reconnect with the server using SSL socket
	if (SSL_connect(SSLSocketForClient) != 1)
	{
		BOOST_LOG_TRIVIAL(error) << "Client: Error SSL_connect";
		closesocket(Client);
		Client = INVALID_SOCKET;
		SSL_free(SSLSocketForClient);
		SSL_CTX_free(ctxForClient);
		return false;
	}
	BOOST_LOG_TRIVIAL(debug) << "Client: Success SSL_connect";
	BOOST_LOG_TRIVIAL(debug) << "Client: End ConnectToserver";

	return true;
}

bool StartVideoClient(void)
{
	hThreadVideoClient = CreateThread(NULL, 0, ThreadVideoClient, NULL, 0, &ThreadVideoClientID);
	return true;
}

bool StopVideoClient(void)
{
	VideoClientSetExitEvent();
	if (hThreadVideoClient != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(hThreadVideoClient, INFINITE);
		CloseHandle(hThreadVideoClient);
		hThreadVideoClient = INVALID_HANDLE_VALUE;
	}
	return true;
}

bool IsVideoClientRunning(void)
{
	if (hThreadVideoClient == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	else return true;
}

static DWORD WINAPI ThreadVideoClient(LPVOID ivalue)
{
	BOOST_LOG_TRIVIAL(debug) << "Client: Start ThreadVideoClient";

	HANDLE ghEvents[3];
	int NumEvents;
	int iResult;
	DWORD dwEvent;
	LARGE_INTEGER liDueTime;
	InputMode Mode = ImageSize;
	unsigned int InputBytesNeeded = sizeof(unsigned int);
	unsigned int SizeofImage;
	char* InputBuffer = NULL;
	char* InputBufferWithOffset = NULL;
	unsigned int CurrentInputBufferSize = 1024 * 10;

	InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
	InputBufferWithOffset = InputBuffer;

	if (InputBuffer == NULL)
	{
		BOOST_LOG_TRIVIAL(error) << "InputBuffer Realloc failed";
		return 1;
	}

	liDueTime.QuadPart = 0LL;

	// 타이머 생성
	// Create timer
	hTimer = CreateWaitableTimer(NULL, FALSE, NULL);

	if (NULL == hTimer)
	{
		BOOST_LOG_TRIVIAL(error) << "CreateWaitableTimer failed " << GetLastError();
		return 2;
	}

	// 타이머 설정
	// Set timer
	if (!SetWaitableTimer(hTimer, &liDueTime, VIDEO_FRAME_DELAY, NULL, NULL, 0))
	{
		BOOST_LOG_TRIVIAL(error) << "SetWaitableTimer failed  " << GetLastError();
		return 3;
	}

	// 클라이언트 이벤트 핸들 생성
	// Create a client event handle
	hClientEvent = WSACreateEvent();

	// 클라이언트 종료 이벤트 핸들 생성
	// Create a client end event handle
	hEndVideoClientEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// 소켓과 이벤트 핸들을 연결 (FD_READ와 FD_CLOSE 이벤트 감시하도록 지정)
	// Connect socket and event handle (specify to watch for FD_READ and FD_CLOSE events)
	if (WSAEventSelect(SSLClient, hClientEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)
	{
		BOOST_LOG_TRIVIAL(error) << "WSAEventSelect() failed with error " << WSAGetLastError();
		iResult = closesocket(Client);
		Client = INVALID_SOCKET;
		SSLClient = INVALID_SOCKET;
		SSL_free(SSLSocketForClient);
		SSL_CTX_free(ctxForClient);
		if (iResult == SOCKET_ERROR)
			BOOST_LOG_TRIVIAL(error) << "closesocket function failed with error : " << WSAGetLastError();
		return 4;
	}

	ghEvents[0] = hEndVideoClientEvent;
	ghEvents[1] = hClientEvent;
	ghEvents[2] = hTimer;
	NumEvents = 3;

	while (1) {
		dwEvent = WaitForMultipleObjects(
			NumEvents,		// number of objects in array
			ghEvents,		// array of objects
			FALSE,			// wait for any object
			INFINITE);		// INFINITE) wait

		// 클라이언트 종료 이벤트
		// Client end event
		if (dwEvent == WAIT_OBJECT_0) break;
		// 클라이언트 소켓의 네트워크 이벤트 처리
		// Handling network events on client socket
		else if (dwEvent == WAIT_OBJECT_0 + 1)
		{
			WSANETWORKEVENTS NetworkEvents;
			// 클라이언트 소켓의 네트워크 이벤트를 가져옴
			// Get network events on client socket
			if (SOCKET_ERROR == WSAEnumNetworkEvents(SSLClient, hClientEvent, &NetworkEvents))
			{
				BOOST_LOG_TRIVIAL(error) << "WSAEnumNetworkEvent: " << WSAGetLastError() << "dwEvent " << dwEvent << " lNetworkEvent " << std::hex << NetworkEvents.lNetworkEvents;
				NetworkEvents.lNetworkEvents = 0;
			}
			else
			{
				if (NetworkEvents.lNetworkEvents & FD_READ)
				{
					if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
					{
						BOOST_LOG_TRIVIAL(error) << "FD_READ failed with error " << NetworkEvents.iErrorCode[FD_READ_BIT];
					}
					else
					{
						int iResult;
						iResult = SSLReadDataTcpNoBlock(SSLSocketForClient, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
						if (iResult != SOCKET_ERROR)
						{
							if (iResult == 0)
							{
								Mode = ImageSize;
								InputBytesNeeded = sizeof(unsigned int);
								InputBufferWithOffset = InputBuffer;
								PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
								BOOST_LOG_TRIVIAL(error) << "Connection closed on Recv";
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
												BOOST_LOG_TRIVIAL(error) << "std::realloc failed ";
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
						//else BOOST_LOG_TRIVIAL(debug) << "Client: SSLReadDataTcpNoBlock buff failed " << WSAGetLastError();
					}
				}
				// 데이터를 전송할 수 있는 상태임을 의미
				if (NetworkEvents.lNetworkEvents & FD_WRITE)
				{
					if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0)
					{
						BOOST_LOG_TRIVIAL(error) << "FD_WRITE failed with error " << NetworkEvents.iErrorCode[FD_WRITE_BIT];
					}
					else
					{
						BOOST_LOG_TRIVIAL(info) << "Client: FD_WRITE";
					}
				}
				// 클라이언트 소켓 닫힘을 의미
				if (NetworkEvents.lNetworkEvents & FD_CLOSE)
				{
					if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)
					{
						BOOST_LOG_TRIVIAL(error) << "FD_CLOSE failed with error " << NetworkEvents.iErrorCode[FD_CLOSE_BIT];
					}
					else
					{
						BOOST_LOG_TRIVIAL(info) << "Client: FD_CLOSE";
						PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
						break;
					}
				}
			}
		}
		// hTimer 이벤트가 발생한 경우, 카메라 프레임을 가져와 서버에 전송
		// Get the camera frame and send it to the server when the hTimer event occurs
		else if (dwEvent == WAIT_OBJECT_0 + 2)
		{
			unsigned int numbytes;

			if (!GetCameraFrame(sendbuff))
			{
				BOOST_LOG_TRIVIAL(info) << "Camera Frame Empty";
			}
			numbytes = htonl((unsigned long)sendbuff.size());
			if (SSLWriteDataTcp(SSLSocketForClient, (unsigned char*)&numbytes, sizeof(numbytes)) == sizeof(numbytes))
			{
				if (SSLWriteDataTcp(SSLSocketForClient, (unsigned char*)sendbuff.data(), (int)sendbuff.size()) != sendbuff.size())
				{
					BOOST_LOG_TRIVIAL(error) << "SSLWriteDataTcp sendbuff.data() Failed " << WSAGetLastError();
					PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
					break;
				}
			}
			else
			{
				BOOST_LOG_TRIVIAL(error) << "SSLWriteDataTcp sendbuff.size() Failed " << WSAGetLastError();
				PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
				break;
			}
		}
	}

	if (InputBuffer)
	{
		std::free(InputBuffer);
		InputBuffer = nullptr;
	}

	VideoClientCleanup();	// 연결이 종료된 서버와 관련된 자원을 정리
	BOOST_LOG_TRIVIAL(info) << "Video Client Exiting";
	return 0;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------