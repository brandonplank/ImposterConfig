//  main.m
//
//  Created by Brandon Plank on 10/1/20.
//  Copyright © 2020 Brandon Plank. All rights reserved.
//

#include <stdio.h>
#include "main.h"
#include <UIKit/UIKit.h>
#include "fishhook.h"
#import <sys/types.h>
#import <sys/socket.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <pthread.h>
#import <errno.h>
#include "BypassAntiDebugging.h"
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#include "plankhooker.h"


// Custom server variables
static NSString *hostName = @"172.105.251.170";
static struct hostent *hostEntry = NULL;
static uint16_t customPort = htons(22023);
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static BOOL canrun = true;


@implementation PatchEntry

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

void *(*orig_sendto)(int socket, const void *buffer, size_t length, int flags, const struct sockaddr *_destination, socklen_t destinationLength);


ssize_t *hook_sendto(int socket, const void *buffer, size_t length, int flags, const struct sockaddr *_destination, socklen_t destinationLength){
    printf("\n\nDumping hex sendto()\n\n");
    DumpHex(buffer, strlen(buffer) + 1);
    if (canrun){
        // Check if the type of the destination structure is sockaddr_in
        if (destinationLength != sizeof(struct sockaddr_in)){
            printf("eat ass one\n");
            return orig_sendto(socket, buffer, length, flags, _destination, destinationLength);
        }
        struct sockaddr_in destination = *(struct sockaddr_in *)_destination;

        // Check if the destination is an Among Us server
        if (destination.sin_family != AF_INET){
            printf("eat ass two\n");
            return orig_sendto(socket, buffer, length, flags, _destination, destinationLength);
        }
        if (destination.sin_port != htons(22023)){
            printf("eat ass three\n");
            return orig_sendto(socket, buffer, length, flags, _destination, destinationLength);
        }

        // Find the IP address of the host specified by the user
        BOOL hostEntryExists = NO;
        pthread_mutex_lock(&mutex);
        if (!hostEntry) {
            hostEntry = gethostbyname(hostName.UTF8String);
        }
        if (hostEntry) {
            hostEntryExists = YES;
        }
        pthread_mutex_unlock(&mutex);

        // If the IP address was found, send the packet to it. If not,
        // fake an error by setting errno to EHOSTUNREACH and returning
        // -1.
        
        if (hostEntryExists) {
            destination.sin_port = customPort;
            bcopy(hostEntry->h_addr, &destination.sin_addr.s_addr, hostEntry->h_length);
            ssize_t ret = orig_sendto(socket, buffer, length, flags, (const struct sockaddr *)&destination, destinationLength);
            return &ret;
        }
        errno = EHOSTUNREACH;
    } else {
        return orig_sendto(socket, buffer, length, flags, _destination, destinationLength);
    }
    return -1;
}


+ (void)load {
    disable_pt_deny_attach();
    disable_sysctl_debugger_checking();
        
    #if TESTS_BYPASS
    test_aniti_debugger();
    #endif
    start();
    [self showAlert];
}

int start(){
    // Its rebind time.
    printf("\n\n\n=========================\nTrying to hook sendto()\n=========================\n\n\n");
    PHook("sendto", hook_sendto, &orig_sendto);
    printf("\n\n\n=========================\nShould have patched sendto()\n=========================\n\n\n");
    return 1;
}

+ (void)showConfig {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        UIViewController * controller = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (controller.presentedViewController) {
            controller = controller.presentedViewController;
        }

        CGRect labelFrame = CGRectMake(controller.view.center.x -150,0, 300, 50);

        UILabel *myLabel = [[UILabel alloc] initWithFrame:labelFrame];
        //If you need to change the color
        [myLabel setTextColor:[UIColor whiteColor]];
        //If you need to change the system font
        [myLabel setFont:[UIFont fontWithName:@"comfortaa" size:15]];
        //If you need alignment
        [myLabel setTextAlignment:NSTextAlignmentCenter];
        // The label will use an unlimited number of lines
        [myLabel setNumberOfLines:0];
        //Add label view to current view
        
        [controller.view addSubview:myLabel];
        NSString *data = [NSString stringWithFormat:@"Server: %@", hostName];
        myLabel.text = data;
        
    });
}

+ (void)showAlert {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        
        UIAlertController * alert=   [UIAlertController
                                      alertControllerWithTitle:@"Imposter Config"
                                      message:@"Enter Server IP and port, if you want to use the defaults to the game, click cancel!\n\nBy pixelomer and Brandon Plank"
                                      preferredStyle:UIAlertControllerStyleAlert];
        UIViewController * controller = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (controller.presentedViewController) {
            controller = controller.presentedViewController;
        }

        UIAlertAction* ok = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault
                                                   handler:^(UIAlertAction * action) {
                                                       //Do Some action here
            hostName = alert.textFields.firstObject.text;
            customPort = atoi([alert.textFields.lastObject.text UTF8String]);
            if ([hostName  isEqual: @""]){
                hostName = @"172.105.251.170";
            }
            if (customPort == 0 || customPort != htons(22023)){
                customPort = htons(22023);
            } else {
                customPort = htons(customPort);
            }
            printf("%s\n%d\n", [hostName UTF8String], customPort);
            [self showConfig];
                                                   }];
        UIAlertAction* cancel = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction * action) {
            canrun = false;
                                                           [alert dismissViewControllerAnimated:YES completion:nil];
                                                        [self showConfig];
                                                       }];

        [alert addAction:ok];
        [alert addAction:cancel];

        [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
            textField.placeholder = @"172.105.251.170 (leave blank for default.)";
        }];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
            textField.placeholder = @"22023 (leave blank for default.)";
            textField.secureTextEntry = YES;
        }];

        [controller presentViewController:alert animated:YES completion:nil];
    });
}

@end
