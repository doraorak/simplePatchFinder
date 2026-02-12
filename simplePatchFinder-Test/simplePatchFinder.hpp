//
//  simplePatchFinder.hpp
//  simplePatchFinder
//
//  Created by Dora Orak on 12.02.2026.
//

#include <iostream>
#include <vector>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>


typedef std::vector<std::pair<std::string, uint64_t>> Instructions; //Vector<pair<mnemonic, address>>

/*
 @abstract: Returns an image (mach header) from its binary name
 
 @param binaryName: binary name of the loaded image. For example just "AppKit" for /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit or "libobjc.A.dylib" for /usr/lib/libobjc.A.dylib
 
 @return: mach header pointer for the target loaded image
 */
const struct mach_header_64* image_getFromBinaryName(const char *binaryName);

/*
 @abstract: finds start addresses of an unique sequence of instruction mnemonics in a given image
 
 @param mh: image (mach header) to look for the target sequence in. You can pass NULL to search in the main executable
 
 @param targetSequence: cpp vector of c strings that contains an exact sequence (so the order matters) of string representations (mnemonics) of arm64 instructions. For example "mov" or "bl".

 @return: cpp vector containing start addresses of the found target sequences of instructions (these addresses take ASLR slide into account, so they should be ready for use)
 
 */
std::vector<uint64_t> image_findInstructions(const struct mach_header_64* mh, std::vector<const char*>&& targetSequence);
