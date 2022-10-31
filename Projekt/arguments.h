//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $arguments.h
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
#include <string>
using namespace std;
struct Options{
    int a_timer;    //active timer value
    int i_timer;    //inactive timer value
    uint32_t count;      //number of  flows in memory
    string hostname; //hostname and optional port
    string source;   //source file
};

void get_options(int argc, char *argv[],Options *);        //process command line arguments

#endif //PROJEKT_ARGUMENTS_H
