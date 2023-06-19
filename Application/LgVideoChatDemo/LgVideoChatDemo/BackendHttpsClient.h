#pragma once
#include <iostream>
#include <map>
#include <string>

int request(std::string request_method, std::string uri, std::string session_token, unsigned int* status_code);
int request(std::string request_method, std::string uri, std::string data, std::string session_token, unsigned int* status_code);
unsigned int backendCheckEmail(const std::string& email);