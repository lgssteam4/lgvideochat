#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* createSSLContextForServer();				// ������ SSL ���ؽ�Ʈ ���� �� �ʱ�ȭ
SSL_CTX* createSSLContextForClient();				// Ŭ���̾�Ʈ�� SSL ���ؽ�Ʈ ���� �� �ʱ�ȭ
SSL* createSSLSocket(SSL_CTX* ctx, int socket);		// SSL ���� ����
void printOpenSSLErrors();							// ���� ���
void handleConnectionEror(SSL* ssl);				// ���� ���� ���� �� ���� ó��

//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
