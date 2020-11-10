### AFLPlusplus

### Ramdisk

AFL benefits from using a ramdisk for the working/output directory.
To setup:

```
mkdir tests/fuzz/results
mount -t tmpfs -o size=8096m ramdisk ./tests/fuzz/results
```

In order for this to work, the docker container must be launched with `--privileged`
Don't forget to  collect the corpus and result files before unmounting the ramdisk.


