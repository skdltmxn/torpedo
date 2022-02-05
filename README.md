# Torpedo

Torpedo is a simple library for PE manipulation. Currently it supports following features.

- PE manual mapping
- PE parsing

## Example

---

### Manual mapping
```c++
#include "torpedo.hpp"

#include <iostream>

void main()
{
    Torpedo::PE dll{"some.dll"};
    Torpedo::ModuleLoader loader;

    auto loadedModule = loader.Load(dll);
    if (!loadedModule)
    {
       std::cerr << "failed to load module" << std::endl;
    }

    return 0;
}
```
