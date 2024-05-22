#!/bin/bash

sudo bpftrace -e 'profile:hz:99999 / comm == ''"'$1'"'' / { @[kstack] = count(); } '
