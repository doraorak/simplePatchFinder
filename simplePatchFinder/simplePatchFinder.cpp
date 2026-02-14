//
//  main.cpp
//  patchFinder
//
//  Created by Dora Orak on 10.02.2026.
//

#include <capstone/capstone.h> // depends on capstone, statically linking against it so our dylib can work standalone
#include <iostream>
//#include <stdio.h>
#include <vector>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

typedef std::vector<std::pair<std::string, uint64_t>> Instructions; //Vector<pair<mnemonic, address>>

/* Finds all starting indices in `big` where `small` matches contiguously
 against `big[i].first` (mnemonic strings), using exact string comparison.*/
 std::vector<size_t> find_subsequence(Instructions& big, std::vector<const char *>& small) {
    std::vector<size_t> result;

    size_t big_len = big.size();
    size_t small_len = small.size();
    
    if (small_len == 0 || small_len > big_len)
        return {};

    for (size_t i = 0; i <= big_len - small_len; i++) {
        bool match = true;

        for (size_t j = 0; j < small_len; j++) {
            if (strcmp(big[i + j].first.c_str(), small[j]) != 0) {
                match = false;
                break;
            }
        }

        if (match) {
            result.push_back(i);
        }
    }

    return result; //returns indexes in vector big, that contains the pairs of interest
}

//gets the slide for a loaded image
intptr_t image_getSlide(const struct mach_header_64 *target) {
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);

        if (mh == target) {
            return _dyld_get_image_vmaddr_slide(i);
        }
    }

    return 0; // not found
}


extern "C" const struct mach_header_64* image_getFromBinaryName(const char *binaryName)
{
    if (!binaryName)
        return NULL;

    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path)
            continue;

        const char *bn = strrchr(path, '/');
        bn = bn ? bn + 1 : path;

        if (strcmp(bn, binaryName) == 0) {
            return (const struct mach_header_64 *)
                _dyld_get_image_header(i);
        }
    }

    return NULL;
}

const struct mach_header_64* image_getMain(){
    uint32_t count = _dyld_image_count();
    const struct mach_header_64* mh = NULL;
    for (uint32_t i = 0; i < count; i++) {
        mh = (const struct mach_header_64*)_dyld_get_image_header(i);
        if (mh->filetype == MH_EXECUTE){
            break;
        }
    }
    
    return mh;
}

std::vector<uint64_t> image_findInstructions(const struct mach_header_64* mh, std::vector<const char*>&& targetSequence) {
    
    if(mh == NULL){
        mh = image_getMain();
    }
    
    intptr_t slide = image_getSlide(mh);
    
    csh handle;
    cs_insn *insn = NULL;
    size_t count;
    
    cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);

    const uint8_t *cmds = (const uint8_t *)(mh + 1);
    
    Instructions instructions = {};
    std::vector<uint64_t> ret = {};

    for (uint32_t cmdIndex = 0; cmdIndex < mh->ncmds; cmdIndex++) {
        const struct load_command *cmd =
            (const struct load_command *)cmds;

        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cmd;

            // Check for executable permission
            if (!(seg->initprot & VM_PROT_EXECUTE)) {
                cmds += cmd->cmdsize;
                continue;
            }

            const struct section_64 *sect =
                (const struct section_64 *)(seg + 1);

            for (uint32_t s = 0; s < seg->nsects; s++) {
                
                uint32_t attrs = sect->flags & SECTION_ATTRIBUTES;
                    
                    // Must contain instructions
                if (!(attrs & (S_ATTR_PURE_INSTRUCTIONS |
                                S_ATTR_SOME_INSTRUCTIONS))) {
                    sect++;
                    continue;
                }
                
                uintptr_t start = (uintptr_t)(sect->addr + slide);
                size_t size = (size_t)sect->size;

                if (size == 0) {
                    sect++;
                    continue;
                }

               // printf("  Segment: %s\n", seg->segname);
               // printf("  Section: %s\n", sect->sectname);
               // printf("  Exec range: %p - %p (size: 0x%zx)\n",(void *)start,(void *)(start + size),size);
                
                uint8_t* code = (uint8_t*)start;
                count = cs_disasm(handle, code, size, start, 0, &insn);
                                
                for (size_t i = 0; i < count; i++) {

                    instructions.push_back(std::pair(insn[i].mnemonic, insn[i].address));

                }
                
                cs_free(insn, count);
                insn = NULL;
                
                sect++;
            }
        }

        cmds += cmd->cmdsize;
    }
    
    auto indexes = find_subsequence(instructions, targetSequence);
    
    if (indexes.empty()){
        return {};
    }
    
    for(auto index : indexes){
        ret.push_back(instructions[index].second);
    }
    
    cs_close(&handle);
    return ret;
    
}

extern "C" uint64_t* image_findInstructions(const struct mach_header_64* mh, char** targetSequence, size_t size){
    
    std::vector<const char*> vec = {};
    
    for (int i = 0; i < size; i++){
        vec.push_back(targetSequence[i]);
    }
    
    std::vector<uint64_t> addresses = image_findInstructions(mh, std::move(vec));
    
    uint64_t* ret = (uint64_t*)malloc(addresses.size() * sizeof(uint64_t));
    
    for (int i = 0; i < addresses.size(); i++){
        ret[i] = addresses.at(i);
    }
    
    return ret;
}
