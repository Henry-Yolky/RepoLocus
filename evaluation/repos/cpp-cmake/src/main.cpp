#include "config.hpp"

int main(int argc, char** argv) {
    return argc > 1 ? parse_port(argv[1]) : 0;
}
