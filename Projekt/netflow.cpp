//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $netflow $netflow.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        netflow.cpp
 * @author      Lucia Makaiová
 *
 * @brief
 */


#include "netflow.h"



using namespace std;

int main(int argc, char **argv) {
    struct Options options = {60,10,1024,"127.0.0.1:2055",""};
    printf("Hello %s", options.hostname);
}