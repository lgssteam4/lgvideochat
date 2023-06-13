#include "ApplyOpenSSL.h"

// ������ SSL ���ؽ�Ʈ ���� �� �ʱ�ȭ
SSL_CTX* createSSLContextForServer()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());    // ���� �� SSL ���ؽ�Ʈ ����
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // �ּ����� ���� ����
    SSL_CTX_set_ecdh_auto(ctx, 1);                      // ECDH �ڵ� ����
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // �ּ����� �������� ���� ����

    // ������ �� ���� Ű �ε�
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// Ŭ���̾�Ʈ�� SSL ���ؽ�Ʈ ���� �� �ʱ�ȭ
SSL_CTX* createSSLContextForClient()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());    // Ŭ���̾�Ʈ �� SSL ���ؽ�Ʈ ����
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // �ּ����� ���� ����
    SSL_CTX_set_ecdh_auto(ctx, 1);                      // ECDH �ڵ� ����
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // �ּ����� �������� ���� ����

    // CA ������ �ε� (������)
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Ŭ���̾�Ʈ ������ �� ���� Ű �ε� (������)
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// SSL ���� ����
SSL* createSSLSocket(SSL_CTX* ctx, int socket)
{
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_set_fd(ssl, socket);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

// ���� ���
void printOpenSSLErrors() 
{
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "OpenSSL Error: %s\n", errorBuffer);
}

// ���� ���� ���� �� ���� ó��
void handleConnectionEror(SSL* ssl)
{
    int error = SSL_get_error(ssl, -1);
    switch (error) {
    case SSL_ERROR_ZERO_RETURN:
        // ���� ����
        break;
    case SSL_ERROR_WANT_READ:
        // �б� ��� ����
        break;
    case SSL_ERROR_WANT_WRITE:
        // ���� ��� ����
        break;
    case SSL_ERROR_SYSCALL:
        if (errno != 0) {
            // �ý��� ȣ�� ����
        }
        else {
            // ���� ���� ����
        }
        break;
    case SSL_ERROR_SSL:
        // SSL ����
        printOpenSSLErrors();
        break;
    default:
        // ��Ÿ ���� ó��
        break;
    }
}
