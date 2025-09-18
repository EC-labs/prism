#!/bin/bash

gcc -o tlpi_select get_num.c error_functions.c select.c
gcc -o tlpi_poll get_num.c error_functions.c poll.c
