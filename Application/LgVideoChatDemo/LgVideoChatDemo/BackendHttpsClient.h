#pragma once
#include <string>

int request(std::string request_method, std::string uri, std::string session_token);
int request(std::string request_method, std::string uri, std::string data, std::string session_token);
