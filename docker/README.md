### Custom docker images for s2n testing

This is a work in progress to automation to automate image creation.

As an example, to build Ubuntu 19.04 with OpenSSL1.1.1:
```
$ gen_compose.py
$ REPOSITORY_URI=localhost docker-compose build ubuntu_19.04_OpenSSL_1_1_1-stable
```