#include <iostream>
#include <istream>
#include <ostream>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/url/src.hpp>
#include <nlohmann/json.hpp>
#include "BackendHttpsClient.h"

using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

const std::string SERVER = "https://20.119.70.194";

class client
{

public:
    client(boost::asio::io_service& io_service,
        boost::asio::ssl::context& ssl_context,
        std::string request_method,
        boost::urls::url const& url,
        std::string session_token
    )
        : resolver_(io_service),
        socket_(io_service, ssl_context)
    {
        // GET request without any data

        const std::string server = url.host();
        const std::string path = url.path();
        const std::string scheme = url.scheme();

        // Form the request. We specify the "Connection: close" header so that the
        // server will close the socket after transmitting the response. This will
        // allow us to treat all data up until the EOF as the content.
        std::ostream request_stream(&request_);
        request_stream << request_method << " " << path << " HTTP/1.1\r\n";
        request_stream << "Host: " << server << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "User-Agent: LG Chat Application/1.0.0\r\n";
        if (!session_token.empty()) {
            request_stream << "Authorization: Bearer " << session_token << "\r\n";
        }
        request_stream << "Connection: close\r\n\r\n";

        // Start an asynchronous resolve to translate the server and service names
        // into a list of endpoints.
        // std::cout << "client: resolving " << server << " (scheme " << scheme << ") ...\n";
        // Always use https for resolving. If the server really is on http only,
        // the resolver will manage it anyways.
        // If your system doesn't define service https (in /etc/services)
        // simply use the port number 443 here.
        tcp::resolver::query query(server, "https");
        resolver_.async_resolve(query,
            boost::bind(&client::handleResolve, this,
                boost::asio::placeholders::error,
                boost::asio::placeholders::iterator));
    }

    client(boost::asio::io_service& io_service,
        boost::asio::ssl::context& ssl_context,
        std::string request_method,
        boost::urls::url const& url,
        std::string data,
        std::string session_token
    )
        : resolver_(io_service),
        socket_(io_service, ssl_context)
    {
        // POST request with data
        const std::string server = url.host();
        const std::string path = url.path();
        const std::string scheme = url.scheme();
        // Form the request. We specify the "Connection: close" header so that the
        // server will close the socket after transmitting the response. This will
        // allow us to treat all data up until the EOF as the content.
        std::ostream request_stream(&request_);
        request_stream << request_method << " " << path << " HTTP/1.1\r\n";
        request_stream << "Host: " << server << "\r\n";
        request_stream << "Accept: */*\r\n";
        if (!session_token.empty()) {
            request_stream << "Authorization: Bearer " << session_token << "\r\n";
        }
        request_stream << "Content-Type: application/x-www-form-urlencoded\r\n";
        request_stream << "Content-Length: " << data.length() << "\r\n";
        request_stream << "Connection: close\r\n\r\n";
        request_stream << data << "\r\n";

        // Start an asynchronous resolve to translate the server and service names
        // into a list of endpoints.
        // std::cout << "client: resolving " << server << " (scheme " << scheme << ") ...\n";
        // Always use https for resolving. If the server really is on http only,
        // the resolver will manage it anyways.
        // If your system doesn't define service https (in /etc/services)
        // simply use the port number 443 here.
        tcp::resolver::query query(server, "https");
        resolver_.async_resolve(query,
            boost::bind(&client::handleResolve, this,
                boost::asio::placeholders::error,
                boost::asio::placeholders::iterator));
    }
    int get_status_code() const {
        return status_code_;
    }

    std::map<std::string, std::string> getKeyValue()
    {
        return keyValuePairs;
    }

private:
    unsigned int status_code_; // 추가

    void handleResolve(const boost::system::error_code& err,
        tcp::resolver::iterator endpoint_iterator)
    {
        if (!err)
        {
            std::cout << "Resolve OK" << "\n";
            socket_.set_verify_mode(boost::asio::ssl::verify_peer);
            socket_.set_verify_callback(
                boost::bind(&client::verifyCertificate, this, _1, _2));

            boost::asio::async_connect(socket_.lowest_layer(), endpoint_iterator,
                boost::bind(&client::handleConnect, this,
                    boost::asio::placeholders::error));
        }
        else
        {
            std::cout << "Error resolve: " << err.message() << "\n";
        }
    }

    bool verifyCertificate(bool preverified,
        boost::asio::ssl::verify_context& ctx)
    {
        std::cout << "verifyCertificate (preverified " << preverified << " ) ...\n";
        // The verify callback can be used to check whether the certificate that is
        // being presented is valid for the peer. For example, RFC 2818 describes
        // the steps involved in doing this for HTTPS. Consult the OpenSSL
        // documentation for more details. Note that the callback is called once
        // for each certificate in the certificate chain, starting from the root
        // certificate authority.

        // In this example we will simply print the certificate's subject name.
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        std::cout << "Verifying " << subject_name << "\n";

        // dummy verification
        return true;
    }

    void handleConnect(const boost::system::error_code& err)
    {
        std::cout << "handleConnect\n";
        if (!err)
        {
            std::cout << "Connect OK " << "\n";
            socket_.async_handshake(boost::asio::ssl::stream_base::client,
                boost::bind(&client::handleHandshake, this,
                    boost::asio::placeholders::error));
        }
        else
        {
            std::cout << "Connect failed: " << err.message() << "\n";
        }
    }

    void handleHandshake(const boost::system::error_code& error)
    {
        std::cout << "handleHandshake start \n";
        if (!error)
        {
            std::cout << "Handshake OK " << "\n";
            std::cout << "Request: " << "\n";
            const char* header = boost::asio::buffer_cast<const char*>(request_.data());
            std::cout << header << "\n";

            // The handshake was successful. Send the request.
            boost::asio::async_write(socket_, request_,
                boost::bind(&client::handleWriteRequest, this,
                    boost::asio::placeholders::error));
        }
        else
        {
            std::cout << "Handshake failed: " << error.message() << "\n";
        }
    }

    void handleWriteRequest(const boost::system::error_code& err)
    {
        std::cout << "handleWriteRequest start \n";
        if (!err)
        {
            // Read the response status line. The response_ streambuf will
            // automatically grow to accommodate the entire line. The growth may be
            // limited by passing a maximum size to the streambuf constructor.
            boost::asio::async_read_until(socket_, response_, "\r\n",
                boost::bind(&client::handleReadStatusLine, this,
                    boost::asio::placeholders::error));
        }
        else
        {
            std::cout << "Error write req: " << err.message() << "\n";
        }
    }

    void handleReadStatusLine(const boost::system::error_code& err)
    {
        std::cout << "handleReadStatusLine start \n";
        if (!err)
        {
            // Check that response is OK.
            std::istream response_stream(&response_);
            std::string http_version;
            response_stream >> http_version;
            unsigned int status_code;
            response_stream >> status_code;
            this->status_code_ = status_code;
            std::string status_message;
            std::getline(response_stream, status_message);

            // Read the response headers, which are terminated by a blank line.
            boost::asio::async_read_until(socket_, response_, "\r\n\r\n",
                boost::bind(&client::handleReadHeaders, this,
                    boost::asio::placeholders::error));

            if (!response_stream || http_version.substr(0, 5) != "HTTP/")
            {
                std::cout << "Invalid response\n";
                return;
            }
            if (status_code != 200)
            {
                std::cout << "Response returned with status code ";
                std::cout << status_code << "\n";
                return;
            }
            std::cout << "Status code: " << status_code << "\n";

        }
        else
        {
            std::cout << "Error: " << err.message() << "\n";
        }
    }

    std::string CopyStreambufToString(std::streambuf* buf) {
        std::stringstream ss;
        ss << buf;
        return ss.str();
    }

    std::map<std::string, std::string> ParseJsonString(const std::string& jsonString) {
        std::map<std::string, std::string> result;

        try {
            // JSON 문자열을 파싱하여 nlohmann::json 객체로 변환
            nlohmann::json json = nlohmann::json::parse(jsonString);

            // json 객체를 순회하면서 key-value 쌍을 추출하여 map에 저장
            for (auto it = json.begin(); it != json.end(); ++it) {
                result[it.key()] = it.value().dump();
            }

            // Remove ""
            for (auto& pair : result) {
                std::string& value = pair.second;
                value.erase(std::remove(value.begin(), value.end(), '\"'), value.end());
            }
        }
        catch (const std::exception& e) {
            std::cout << "Error parsing JSON: " << e.what() << std::endl;
        }

        return result;
    }

    void handleReadHeaders(const boost::system::error_code& err)
    {
        std::cout << "handleReadHeaders\n";
        if (!err)
        {
            // Process the response headers.
            std::istream response_stream(&response_);
            std::string header;
            while (std::getline(response_stream, header) && header != "\r")
                std::cout << header << "\n";
            std::cout << "\n";

            // Write whatever content we already have to output.
            if (response_.size() > 0)
            {
                std::string str = CopyStreambufToString(&response_);
                std::cout << "content string : " << str << std::endl;
                keyValuePairs = ParseJsonString(str);
            }

            // Start reading remaining data until EOF.
            boost::asio::async_read(socket_, response_,
                boost::asio::transfer_at_least(1),
                boost::bind(&client::handleReadContent, this,
                    boost::asio::placeholders::error));
        }
        else
        {
            std::cout << "Error: " << err << "\n";
        }
    }

    void handleReadContent(const boost::system::error_code& err)
    {
        if (!err)
        {
            // Write all of the data that has been read so far.
            std::cout << &response_;

            // Continue reading remaining data until EOF.
            boost::asio::async_read(socket_, response_,
                boost::asio::transfer_at_least(1),
                boost::bind(&client::handleReadContent, this,
                    boost::asio::placeholders::error));
        }
        else if (err != boost::asio::error::eof)
        {
            std::cout << "Error: " << err << "\n";
        }
    }

    tcp::resolver resolver_;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    boost::asio::streambuf request_;
    boost::asio::streambuf response_;
    std::map<std::string, std::string> keyValuePairs;
};


int request(std::string request_method, std::string uri, std::string session_token,
    unsigned int* status_code, std::map<std::string, std::string>& response)
{
    try
    {
        // Parse an URL. This allocates no memory. The view
        // references the character buffer without taking ownership.
        std::string url_string = SERVER + uri;
        std::cout << url_string << std::endl;
        boost::urls::url_view uv(url_string);
        // Create a modifiable copy of `uv`, with ownership of the buffer
        boost::urls::url url = uv;

        boost::asio::io_context io_context;

        // Create a SSL context that uses the default paths for finding CA certificates:
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);
        ssl_context.set_default_verify_paths();

        client c(io_context, ssl_context, request_method, url, session_token);
        io_context.run();
        *status_code = c.get_status_code();
        std::cout << "status_code : " << *status_code << "\n";
        response = c.getKeyValue();
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}

int request(std::string request_method, std::string uri, std::string data, std::string session_token,
    unsigned int* status_code, std::map<std::string, std::string>& response)
{
    try
    {
        // Parse an URL. This allocates no memory. The view
        // references the character buffer without taking ownership.
        std::string url_string = SERVER + uri;
        std::cout << url_string << std::endl;
        boost::urls::url_view uv(url_string);
        // Create a modifiable copy of `uv`, with ownership of the buffer
        boost::urls::url url = uv;

        boost::asio::io_context io_context;

        // Create a SSL context that uses the default paths for finding CA certificates:
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);
        ssl_context.set_default_verify_paths();

        client c(io_context, ssl_context, request_method, url, data, session_token);
        io_context.run();
        *status_code = c.get_status_code();
        std::cout << "status_code : " << *status_code << "\n";
        response = c.getKeyValue();
    }
    catch (std::exception& e)
    {
        std::cout << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}

unsigned int sendGetRequest(const std::string& function, const std::string& sessionToken) {
    int rc = 0;
    unsigned int statusCode = 0;
    std::map<std::string, std::string> response;

    // Send GET request
    rc = request("GET", function, sessionToken, &statusCode, response);
    std::cout << "GET : statusCode - " << statusCode << std::endl;
    // 3rd param is session token

    for (const auto& pair : response) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }

    return statusCode;
}

unsigned int sendPostRequest(const std::string& function, const std::string& data, const std::string& sessionToken) {
    int rc = 0;
    unsigned int statusCode = 0;
    std::map<std::string, std::string> response;

    rc = request("POST", function, data, sessionToken, &statusCode, response);
    std::cout << "POST : statusCode - " << statusCode << std::endl;
    // 3rd param is session token

    for (const auto& pair : response) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }

    return statusCode;
}

unsigned int sendPostRequest(const std::string& function, const std::string& data,
    const std::string& sessionToken, std::map<std::string, std::string>& response) {
    int rc = 0;
    unsigned int statusCode = 0;

    rc = request("POST", function, data, sessionToken, &statusCode, response);
    std::cout << "POST : statusCode - " << statusCode << std::endl;
    // 3rd param is session token

    for (const auto& pair : response) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }

    return statusCode;
}
