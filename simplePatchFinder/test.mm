//
//  test.cpp
//  patchFinder
//
//  Created by Dora Orak on 11.02.2026.
//

#import <Foundation/Foundation.h>
#import "simplePatchFinder.hpp"


int main(void){
    
    const struct mach_header_64* mh = image_createFromBinaryName("Foundation");
    
    auto results = image_findInstructions(mh, {"pacibsp", "stp", "stp"});
    
    std::cout << results[0] << std::endl;
    
}
