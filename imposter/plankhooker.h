//
//  plankhooker.h
//  imposter
//
//  Created by Brandon Plank on 10/12/20.
//  Copyright © 2020 Brandon Plank. All rights reserved.
//

#ifndef plankhooker_h
#define plankhooker_h

#include <stdio.h>

void PHook(const char *symbol, void *new_function, void **old_function);

#endif /* plankhooker_h */
