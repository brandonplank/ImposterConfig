//
//  plankhooker.c
//  imposter
//
//  Created by Brandon Plank on 10/12/20.
//  Copyright © 2020 Brandon Plank. All rights reserved.
//

// Basic wrapper for fishhook.

#include "plankhooker.h"
#include "fishhook.h"
#import <dlfcn.h>
#import <sys/sysctl.h>

void PHook(const char *symbol, void *new_function, void **old_function){
    printf("[PlankHooker] Rebinding %s\n", symbol);
    void *orig;
    *old_function = dlsym(RTLD_DEFAULT, symbol);
    rebind_symbols((struct rebinding[1]){{symbol, new_function}}, 1);
    printf("[PlankHooker] Rebindnded %s:0x%02x to 0x%02x\n", symbol, (uint8_t*)new_function, (uint8_t)old_function);
}
