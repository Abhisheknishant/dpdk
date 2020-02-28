#!/bin/sh -xe

# need to install as 'root' since some of the unit tests won't run without it
sudo python3 -m pip install --upgrade 'meson==0.47.1'

# set up hugepage if fast-tests suite (default) will run
if [ "$RUN_TESTS" = "1" ]; then
    for testsuite in ${TEST_SUITES:-fast-tests}; do
        if [ "$testsuite" = "fast-tests" ]; then
            # setup hugepages
            cat /proc/meminfo
            sudo sh -c 'echo 1024 > /proc/sys/vm/nr_hugepages'
            cat /proc/meminfo

            break
        fi
    done
fi
