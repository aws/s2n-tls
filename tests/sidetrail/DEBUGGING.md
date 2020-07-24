# Debugging SideTrail

This is a guide for what to do when SideTrail reports a potential timing violation / throws a red `x` in CI.



## Running SideTrail inside a docker image

We assume you have docker installed and running on your machine.
If not, follow the instructions to install it https://docs.docker.com/get-docker/

We will assume that you have a variable `$S2N` which encodes the path to s2n on your machine

```shell
export S2N=<path_to_s2n>
```

### Building the image

To build the image, start with `s2n/codebuild/spec/sidetrail/Dockerfile`

```shell
cd $S2N
docker build -f codebuild/spec/sidetrail/Dockerfile --tag sidetrail2 .
```

This step takes about 25 minutes on my laptop.

### Starting docker

```shell
cd $S2N
docker run -it -v `pwd`:/home/s2n --entrypoint /bin/bash sidetrail
```

You will now be presented with a docker shell.
Inside this shell, run:

```shell
source /sidetrail-install-dir/smack.environment 
```

This step is important.
If you do not source this file when you begin working, SideTrail may appear to run, but not actually analyze the code.

### Running a proof inside docker


```shell
cd /home/s2n/tests/sidetrail/working
cd <testname>
./clean.sh ; ./run.sh
```

You should see output that looks something like this 

```
...
...
warning: memory intrinsic length exceeds threshold (0); adding quantifiers.
SMACK generated s2n_record_parse_wrapper@s2n_record_read_wrapper.c.compiled.bpl
warning: module contains undefined functions: malloc, __CONTRACT_invariant, nondet

 ____                _            _   
|  _ \ _ __ ___   __| |_   _  ___| |_ 
| |_) | '__/ _ \ / _` | | | |/ __| __|
|  __/| | | (_) | (_| | |_| | (__| |_ 
|_|   |_|  \___/ \__,_|\__,_|\___|\__|
                                      
s2n_record_parse_wrapper@s2n_record_read_wrapper.c



__     __        _  __       
\ \   / /__ _ __(_)/ _|_   _ 
 \ \ / / _ \ '__| | |_| | | |
  \ V /  __/ |  | |  _| |_| |
   \_/ \___|_|  |_|_|  \__, |
                       |___/ 
s2n_record_parse_wrapper@s2n_record_read_wrapper.c

+  boogie /printModel 4 /doModSetAnalysis s2n_record_parse_wrapper@s2n_record_read_wrapper.c.product.bpl
Boogie program verifier version 2.3.0.61016, Copyright (c) 2003-2014, Microsoft.

Boogie program verifier finished with 1 verified, 0 errors

real	0m23.334s
user	0m20.983s
sys	0m2.395s
```

If you do not see the line, 

```
Boogie program verifier finished with 1 verified, 0 errors
```

then you probably forgot to source `smack.environment`.
Go back and do so.

## Known issues

### Known undefined functions

You may see a warning like:

```
warning: module contains undefined functions: malloc, __CONTRACT_invariant, nondet
```

This is expected.
It signifies that SMACK does not have a model for the function.
If it is one of the functions listed as `allowed_undefined` in https://github.com/awslabs/s2n/blob/master/tests/sidetrail/count_success.pl#L33 then this is not a problem.
If it is a different function, not listed as one of these, contact your friendly neighbourhood automated reasoning expert for guidence.
Either the function is safe to leave without a timing model, in which case you can add it to the list in `count_success.pl`.
Or, it requires a model to be written.

[TODO] Details on how to write a timing model.

## Updating the patch files

## Expected runtimes:

| Test name                         | Runtime | 
| --------------------------------- | ------: |
| s2n-record-read-cbc-negative-test | 20s     |
| s2n-cbc                           | 5m 45s  |
| s2n-record-read-composite         | 15s     |
| s2n-record-read-aead              | 4m 10s  |
| s2n-record-read-stream            | 25s     |
| s2n-record-read-cbc               | 20s     |

