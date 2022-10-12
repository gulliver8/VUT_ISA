//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $netflow $arguments.h
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        arguments.h
 * @author      Lucia Makaiová
 *
 * @brief
 */


#ifndef PROJEKT_ARGUMENTS_H
#define PROJEKT_ARGUMENTS_H
#include <getopt.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <time.h>
using namespace std;
typedef struct{
    int a_timer;    //active timer value
    int i_timer;    //inactive timer value
    int count;      //number of  flows in memory
    char *hostname; //hostname and optional port
    char *source;   //source file
}Options;

void get_options(int argc, char *argv[],Options *options);        //process command line arguments

#endif //PROJEKT_ARGUMENTS_H
