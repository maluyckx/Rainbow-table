#include <iostream>
#include "sha256.h"
#include "staticstring.hpp"
 
int main(int argc, char *argv[])
{   
    std::string input1 = "grape";        
    std::string output1 = sha256(input1);
 
    std::cout << "sha256('"<< input1 << "'):" << output1 << std::endl;
    
    StaticString<6> input2 = "grape";
    StaticString<65> output2 = sha256(input2);

    std::cout << "sha256('"<< input2 << "'):" << output2 << std::endl;
    return 0;
}
