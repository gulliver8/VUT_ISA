//
// Created by student on 12.10.22.
//

#include<stdio.h>
#include"arguments.h"

/**
 * process command line arguments
 * MODIFICATED from
 * SOURCE: https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 * AUTHOR: Free Software Foundation, Inc.
 * COPYRIGHT: Copyright © 1993–2022 Free Software Foundation, Inc.
 */

void get_options(int argc, char *argv[], Options *options) {
    int input;
    while ((input = getopt(argc, argv, ":h:f:c:a:i:m:tu")) != -1) {
        switch (input) {
            case 'h':
                printf("help"); //TODO
                break;
            case 'f':
                options->source = optarg;
                break;
            case 'c':
                options->hostname = optarg;
                break;
            case 'a':
                if((options->a_timer = atoi(optarg)) == 0)
                    exit(1);
                break;
            case 'i':
                if((options->i_timer = atoi(optarg)) == 0)
                    exit(1);
                break;
            case 'm':
                if((options->count = atoi(optarg)) == 0)
                    exit(1);
                break;
            case '?':
                fprintf(stderr, "invalid option: -%c\n", optopt);
                exit(1);
                break;
            case ':':
                if (optopt != 'i') {
                    fprintf(stderr, "option -%c is missing a required argument\n", optopt);
                    exit(1);
                }
            default:
                break;
        }
    }
}