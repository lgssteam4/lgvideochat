#include "ApplyOpenSSL.h"

// 서버측 SSL 컨텍스트 생성 및 초기화
SSL_CTX* createSSLContextForServer()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());    // 서버 측 SSL 컨텍스트 생성
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // 최소한의 보안 설정
    SSL_CTX_set_ecdh_auto(ctx, 1);                      // ECDH 자동 설정
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // 최소한의 프로토콜 버전 설정

    // 인증서 및 개인 키 로드
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

// 클라이언트측 SSL 컨텍스트 생성 및 초기화
SSL_CTX* createSSLContextForClient()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());    // 클라이언트 측 SSL 컨텍스트 생성
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // 최소한의 보안 설정
    SSL_CTX_set_ecdh_auto(ctx, 1);                      // ECDH 자동 설정
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // 최소한의 프로토콜 버전 설정

    // CA 인증서 로드 (선택적)
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // 클라이언트 인증서 및 개인 키 로드 (선택적)
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

// SSL 소켓 생성
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

// 오류 출력
void printOpenSSLErrors() 
{
    char errorBuffer[256];
    ERR_error_string_n(ERR_get_error(), errorBuffer, sizeof(errorBuffer));
    fprintf(stderr, "OpenSSL Error: %s\n", errorBuffer);
}

// 소켓 연결 종료 및 에러 처리
void handleConnectionEror(SSL* ssl)
{
    int error = SSL_get_error(ssl, -1);
    switch (error) {
    case SSL_ERROR_ZERO_RETURN:
        // 연결 종료
        break;
    case SSL_ERROR_WANT_READ:
        // 읽기 대기 상태
        break;
    case SSL_ERROR_WANT_WRITE:
        // 쓰기 대기 상태
        break;
    case SSL_ERROR_SYSCALL:
        if (errno != 0) {
            // 시스템 호출 에러
        }
        else {
            // 소켓 연결 종료
        }
        break;
    case SSL_ERROR_SSL:
        // SSL 오류
        printOpenSSLErrors();
        break;
    default:
        // 기타 오류 처리
        break;
    }
}
