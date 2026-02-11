//
//  test.cpp
//  patchFinder
//
//  Created by Dora Orak on 11.02.2026.
//

#import <Foundation/Foundation.h>
#import "simplePatchFinder.hpp"


int main(void){
    
    const struct mach_header_64* mh = image_getFromBinaryName("libobjc.A.dylib");
    
    auto results = image_findInstructions(mh, {"pacibsp"});
    
    std::cout << results[0] << std::endl;
    
}
