#include<iostream>
#include "ta.hpp"
using namespace ps;
int main() {
    ps::init_relic();
    TA ta;
    ta.setup();
    ta.export_global_params_to_file("global_params.dat");
    std::cout << "TA initialized and set global parameters." << std::endl;
    return 0;
}