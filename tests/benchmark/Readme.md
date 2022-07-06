# s2n-tls Benchmarking
This README covers the basics on how to build the s2n-tls library to be able to use Google Benchmark in running the s2n-tls benchmarks.
##Install Google Benchmark
Follow instructions on the Google Benchmark repository to build and install [Google Benchmark](https://github.com/google/benchmark)

## Building the s2n-tls library
#### In order to enable the s2n library to build the benchmarks the following parameters must be set:
1. `-DBUILD_TESTING=1`
2. `-DBENCHMARK=1`
3. `-DCMAKE_PREFIX_PATH="File/path/to/Google/Benchmark/"`

#### Example:

```
# Starting from the top level "s2n-tls" directory, remove previous CMake build files, if any
rm -rf build

# Initialize CMake build directory with Nina build system
cmake . -Bbuild -GNinja -DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=1 -DBENCHMARK=1 -DCMAKE_PREFIX_PATH="~/benchmark/install"

# Actually build the executable binaries
cd build
ninja

# Run a benchmark
./bin/s2n_negotiate_benchmark -r 1 -i 5 -p ../tests/pems/ -o negotiate_data -t console localhost 8000 
```

**If you would like to build with a different libcrypto, include the file path in -DCMAKE_PREFIX_PATH**:

`-DCMAKE_PREFIX_PATH="~/aws-lc/install;~/benchmark/install"`

## Running benchmarks
Once the s2n-tls library has completed building, the benchmarks can be located in the `build/bin` folder.
The two benchmarks that are currently available are `s2n_negotiate_benchmark` and `s2n_send_recv_benchmark`

### Benchmark Options:
Each benchmark has the ability to accept different options:

usage: 

    *s2n_benchmark* [options] host port

    host: hostname or IP address to connect to
    port: port to connect to
###### Options:
    -i [# of iterations]
    sets the number of iterations to run each repetition

    -r [# of repetitions]
    sets the number of repetitions to run each benchmark

    -w [# of warmup iterations]
    sets the number of warmup runs for each benchmark

    -o [output file name]
    sets the name of the output file

    -t [json|csv|console]
    sets the output format of the output file

    -p [file path to pem directory]
    if using secure mode, must set pem directory

    -g [google benchmark options]
    sets the google benchmark options

    -d [#;#;#]
    sets the size of the data that should be sent in send/recv benchmarks

    -s 
    run benchmarks in insecure mode

    -c
    sets use_corked_io to true

    -D
    print debug output to terminal
    

### s2n_negotiate_benchmark
Example: 

`./bin/s2n_negotiate_benchmark -r 1 -i 5 -p ../tests/pems/ -o negotiate_data -t console localhost 8000`

or

`./bin/s2n_negotiate_benchmark -r 5 -i 5 -w 10 -p ../tests/pems/ -o negotiate_data -t console localhost 8000`



