#include <string>
#include <sstream>
#include <cstdio>
#include <memory>
#include <iostream>

using std::string;
using std::shared_ptr;
using std::stringstream;
stringstream
exec(const char* cmd) {
    std::array<char, 128> buffer;
    stringstream result;
    shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result << buffer.data();
    }
    return result;
}

void
parse_arg(int argc, char *argv[], string &arg1) {
    stringstream s;
    for (int i = 1; i < argc; ++i) {
        s << argv[i] << " ";
    }
    arg1 = s.str();
    return;
}

int
main(int argc, char *argv[]) {
    string arg1, exec_cmd;
    string executible = "/sbin/iptables-1.4.7 main";
    parse_arg(argc, argv, arg1);
    exec_cmd = executible + " " + arg1;
    exec("iptables-restore /etc/sysconfig/iptables");
    stringstream result = exec(exec_cmd.c_str());
    std::cout << result.str() << std::endl;
}
