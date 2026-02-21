//
//  main.m
//  simplePatchFinder-Test
//
//  Created by Dora Orak on 12.02.2026.
//

#include "simplePatchFinder.h" //you have to add libsimplePatchFinder.dylib to general->"Libraries and Frameworks" in target settings
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>

int main(int argc, const char * argv[] ) {
    void* handle = dlopen("/usr/lib/system/libdyld.dylib", 0);
    
    const struct mach_header_64* mh = image_getFromBinaryName("libdyld.dylib");
   
    const std::vector<uint64_t> results = image_findInstructions(mh, {"pacibsp", "stp * * [sp, #-0x20]!", "stp", "add", "mov x19 x0", "adrp", "ldr", "cmn x8", "b.ne", "adrp", "ldr", "cbz", "ldr", "mov", "ldp", "ldp", "autibsp", "eor x16", "tbz x16 #0x3e", "brk", "braaz x1", "mov", "ldp", "ldp", "autibsp", "eor", "tbz x16 * #0x1828d97f8", "brk #0xc471", "b", "bl", "b"});
    
    std::cout << results.size() << std::endl;
 /*
    char* ins[9] = {"pacibsp", "sub", "stp", "stp", "stp", "add", "mov", "mov", "cmp"};
    size_t outcount;
    uint64_t* cresults = image_findInstructions(mh, ins, 9, &outcount); //also works in cpp
 */
    if (!results.empty()){
        uint64_t add = results[0];
        
        
        int64_t addr = ((int64_t(*)())add)();
    }
    return 1;
    
}

/* C binding usage example
 main.c file:
 
 #include "simplePatchFinder.h"
 #include <dlfcn.h>

 int main(int argc, const char * argv[] ) {
     void* handle = dlopen("/usr/lib/system/libdyld.dylib", 0);
     
     const struct mach_header_64* mh = image_getFromBinaryName("libdyld.dylib");
     
     char* ins[9] = {"pacibsp", "sub", "stp", "stp", "stp", "add", "mov", "mov", "cmp"};

     size_t outcount = 0;
 
     uint64_t* results = image_findInstructions(mh, ins, 9, &outcount); //3rd parameter is instructions count, 4th parameter is a pointer to size_t, upon return it contains how many entries there are in the result array
         
     uint64_t add = results[0];
     
     ((char*(*)(uint64_t))add)((uint64_t)mh);
  
     return 1;
     
 }
 */

/*
 Swift/objc++ bridging and wrapper example:
 
 #import <Foundation/Foundation.h>
 #import "simplePatchFinder.hpp"

 NSArray* swift_findInstructions(const struct mach_header_64* mh, NSArray* arr){
     
     std::vector<const char*> vec = {};
     
     for (NSString* str in arr){
         vec.push_back(str.UTF8String);
     }
     
     auto results = image_findInstructions(mh, std::move(vec));
     
     NSMutableArray* ret = [NSMutableArray array];
     
     for (uint64_t index : results){
         [ret addObject:@(index)];
     }
     
     return ret;
 }
 
Change the swift/objc interoperability mode to swift/objc++ from project settings.
After that use a bridging header to expose this objc++ function to swift.
When used from swift it takes a swift array of swift strings for the second argument
 
 */
