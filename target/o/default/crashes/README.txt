Command line used to find this crash:

afl-fuzz -t 500 -m 2048 -i in -o out ./app

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 2.00 GB.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
an mail at <afl-users@googlegroups.com> once the issues are fixed

  https://github.com/AFLplusplus/AFLplusplus

