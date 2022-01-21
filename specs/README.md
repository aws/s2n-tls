### RPM for s2n-tls

#### Amzn2022/Fedoracore35

```
mkdir -p ~/rpmbuild/SOURCES ~/rpmbuild/SPECS
cp ./specs/s2n-tls.al2022.spec ~/rpmbuild/SPECS/
cd ~/rpmbuild
curl https://codeload.github.com/aws/s2n-tls/tar.gz/refs/tags/v1.3.4 -o ./SOURCES/s2n-tls-1.3.4.tar.gz
yum install -y mock gcc openssl cmake openssl-devel ninja-build rpm-build
rpmbuild -ba ./SPECS/s2n-tls.spec
```


#### Testing rpm changes

Use [mock](https://rpm-software-management.github.io/mock/) after completing the above (or fetch srpm from elsewhere):
```
mock ~/rpmbuild/SRPMS/s2n-tls-<Version>.<dist>.src.rpm
```


