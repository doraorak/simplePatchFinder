//
//  main.m
//  simplePatchFinder-Test
//
//  Created by Dora Orak on 12.02.2026.
//

#import <Foundation/Foundation.h>
#import "simplePatchFinder.hpp" //you have to add libsimplePatchFinder.dylib to general->"Libraries and Frameworks" in target settings
#import <mach-o/loader.h>
#include <mach-o/dyld.h>

extern "C" __attribute__((noinline, used, section("__TEXT,__text")))
void asmfun() {
    __asm__ volatile (
        // do some simple work
        "mov x0, #42\n"        //  x0 = 42
        "mov x1, #10\n"        // x1 = 10
        "add x0, x0, x1\n"    // x0 = 52
        "sub x0, x0, x1\n"
    );
}

int main(int argc, const char * argv[]) {
    
    const std::vector<uint64_t> results = image_findInstructions(0, {"mov", "mov", "add", "sub"});
    
    std::cout << results.size() << std::endl;
 
    return 1;
    
}

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
