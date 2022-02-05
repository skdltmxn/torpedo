#include "torpedo.hpp"

#include <iostream>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <dll path>" << std::endl;
        return 1;
    }

    Torpedo::PE ntdll{argv[1]};
    Torpedo::ModuleLoader loader;

    auto module = loader.Load(ntdll);
    if (not module)
    {
        std::cerr << "failed to load module" << std::endl;
    }

    return 0;
}
