//
//  main.m
//  simplePatchFinder-Test
//
//  Created by Dora Orak on 12.02.2026.
//



#import <Foundation/Foundation.h>
#import "simplePatchFinder.hpp" //you have to add libsimplePatchFinder.dylib to general->"Libraries and Frameworks" in target settings

int main(int argc, const char * argv[]) {
    
    const struct mach_header_64* mh = image_getFromBinaryName("Foundation");
    
    auto results = image_findInstructions(mh, {"pacibsp", "stp", "stp", "stp"});
    
    std::cout << results[0] << std::endl;
 
    return 1;
    
}
