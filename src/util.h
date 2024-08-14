#pragma once

#include <iostream>
#include <cstdio>
#include <memory>
#include <string>
#include <algorithm>
#include <regex>


std::string trim(const std::string &str);
std::string get_my_mac(const std::string &interface);
std::string get_my_ip(const std::string &interface);
std::string mac_to_string(uint8_t *mac);
