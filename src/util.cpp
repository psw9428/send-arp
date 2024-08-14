#include "util.h"
#include "mac.h"

std::string trim(const std::string &str)
{
    auto start = str.begin();
    while (start != str.end() && isspace(*start)) start++;

    auto end = str.end();
    do {
        end--;
    } while (distance(start, end) > 0 && isspace(*end));

    return std::string(start, end + 1);
}

std::string get_my_mac(const std::string &interface) {
    std::string cmd = "ifconfig "+interface+" | grep ether | awk -F \" \" \'{print $2}\'";
    std::string result = "";
    std::regex pattern(R"(^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$)");
    char buf[128];

    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("[*] popen() failed!");

    while (fgets(buf, sizeof(buf), pipe.get()) != nullptr) result += buf;
    result = trim(result);

    if (result.length() != 17 || !std::regex_match(result, pattern))
        throw std::runtime_error("Can't get " + interface + " MAC address! Check your network connection or interface.");

    return result;
}

std::string get_my_ip(const std::string &interface) {
    std::string cmd = "ifconfig " + interface + " | grep \'inet \' | awk -F \" \" \'{print $2}\'";
    std::string result = "";
    std::regex pattern(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)");
    char buf[128];

    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");

    while (fgets(buf, sizeof(buf), pipe.get()) != nullptr) result += buf;
    result = trim(result);

    if (!std::regex_match(result, pattern))
        throw std::runtime_error("Can't read ip address! Check your network connection or interface.");

    return result;
}
