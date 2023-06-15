#include "ApplyOpenSSL.h"
#include <iostream>

// ������ SSL ���ؽ�Ʈ ���� �� �ʱ�ȭ
SSL_CTX* createSSLContextForServer()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());    // ���� �� SSL ���ؽ�Ʈ ����
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        std::cout << "[Test.lim] Error: SSL_CTX_new" << std::endl;
        return NULL;
    }

    // �ּ����� ���� ����
    //SSL_CTX_set_ecdh_auto(ctx, 1);                      // ECDH �ڵ� ����
    //SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); // �ּ����� �������� ���� ����

    // ������ �� ���� Ű �ε�
    if (SSL_CTX_use_certificate_file(ctx, "keyandcert/certificate.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cout << "[Test.lim] Error: SSL_CTX_use_certificate_file" << std::endl;
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "keyandcert/private.key", SSL_FILETYPE_PEM) <= 0) {
        std::cout << "[Test.lim] Error: SSL_CTX_use_PrivateKey_file" << std::endl;
        SSL_CTX_free(ctx);
        return NULL;
    }

    // ���� Ű�� ��� ������ ������ Ȯ��
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cout << "[Test.lim] Error: SSL_CTX_check_private_key" << std::endl;
        return NULL;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // SSL ���� ĳ�� ��Ȱ��ȭ
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    return ctx;
}

// Ŭ���̾�Ʈ�� SSL ���ؽ�Ʈ ���� �� �ʱ�ȭ
SSL_CTX* createSSLContextForClient()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());    // Ŭ���̾�Ʈ �� SSL ���ؽ�Ʈ ����
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        std::cout << "[Test.lim] Error: SSL_CTX_new" << std::endl;
        return NULL;
    }

    // �ּ����� ���� ����
    //SSL_CTX_set_ecdh_auto(ctx, 1);                      // ECDH �ڵ� ����
    //SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); // �ּ����� �������� ���� ����
/*
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
*/
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // SSL ���� ĳ�� ��Ȱ��ȭ
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    return ctx;
}

// SSL ���� ����
SSL* createSSLSocket(SSL_CTX* ctx, int socket)
{
    //unsigned long err;
    //char err_buf[256];

    if (socket == -1) {
        std::cout << "[Test.lim] Error: socket is -1" << std::endl;
        return NULL;
    }

    // SSL ���� ����
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cout << "[Test.lim] Error: SSL_new" << std::endl;
        return NULL;
    }

    // SSL ���Ͽ� �Ϲ� ���� ����
    int fd = SSL_set_fd(ssl, socket);
    if (fd != 1)
    {
        std::cout << "[Test.lim] Error: SSL_set_fd" << std::endl;
        SSL_free(ssl);
        return NULL;
    }

    // SSL/TLS �ڵ����ũ ����
    int ret = SSL_accept(ssl);
    if (ret != 1) {
        std::cout << "[Test.lim] Error: SSL_accept ret " << ret << std::endl;
        handleConnectionEror(ssl, ret);
        //err = ERR_get_error();
        //ERR_error_string(err, err_buf);
        //std::cout << "[Test.lim] " << err_buf << std::endl;
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

// OpenSSL �ʱ�ȭ
void initializeSSL()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

// ���� ���
void printOpenSSLErrors() 
{
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    //fprintf(stderr, "OpenSSL Error: %s\n", errorBuffer);
    std::cout << "[Test.lim] OpenSSL Error: " << errorBuffer << std::endl;
}

// ���� ���� ���� �� ���� ó��
void handleConnectionEror(SSL* ssl, int ret)
{
    int error = SSL_get_error(ssl, ret);
    switch (error) {
    case SSL_ERROR_ZERO_RETURN:
        // ���� ����
        std::cout << "[Test.lim] Error: SSL_ERROR_ZERO_RETURN" << std::endl;
        break;
    case SSL_ERROR_WANT_READ:
        // �б� ��� ����
        std::cout << "[Test.lim] Error: SSL_ERROR_WANT_READ" << std::endl;
        break;
    case SSL_ERROR_WANT_WRITE:
        // ���� ��� ����
        std::cout << "[Test.lim] Error: SSL_ERROR_WANT_WRITE" << std::endl;
        break;
    case SSL_ERROR_SYSCALL:
        if (errno != 0) {
            // �ý��� ȣ�� ����
            std::cout << "[Test.lim] Error: SSL_ERROR_SYSCALL (Error system call)" << std::endl;
        }
        else {
            // ���� ���� ����
            std::cout << "[Test.lim] Error: SSL_ERROR_SYSCALL (Terminate socket connection)" << std::endl;
        }
        break;
    case SSL_ERROR_SSL:
        // SSL ����
        printOpenSSLErrors();
        break;
    default:
        // ��Ÿ ���� ó��
        std::cout << "[Test.lim] Error: Etc....." << std::endl;
        break;
    }
}
