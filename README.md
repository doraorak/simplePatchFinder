# Info
This is a single header cpp library that uses capstone (https://www.capstone-engine.org) to find start addresses of an unique sequence of instructions in a given image (main executable, dylib or a framework)

# API
### `std::vector<uint64_t> image_findInstructions(const struct mach_header_64* mh, std::vector<const char*>&& targetSequence)`

- `mh`: image (mach header) to look for the target sequence in. You can pass NULL to search in the main executable

- `targetSequence`: cpp vector of c strings that contains an exact sequence (so the order matters) of string representations (mnemonics) of arm64 instructions. For example "mov" or "bl".
  
- `return`: a cpp vector of start addresses of the found target sequences of instructions (these addresses take ASLR slide into account, so they should be ready for use)

### `const struct mach_header_64* image_createFromBinaryName(const char *binaryName)`
- `binaryName`: binary name of the loaded image. For example just "AppKit" for /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit or "libobjc.A.dylib" for /usr/lib/libobjc.A.dylib

- `return`: a mach header pointer for the target loaded image

# Dependencies

Depends on capstone library, see https://www.capstone-engine.org for installation tutorial

# Example 

see test.mm file. 
```cpp
#include "simplePatchFinder.hpp"
const struct mach_header_64* mh = image_createFromBinaryName("libobjc.A.dylib");
image_findInstructions(mh, {"pacibsp", "stp", "stp"});
```
