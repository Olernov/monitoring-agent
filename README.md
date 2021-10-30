[[_TOC_]]

# Automated builds guide
Read me on automated compile & packaging guide in [packaging readme](packaging/README.md).

ℹ Especially, you may be interested in automated environment prepare script `checkenv.sh`, which mostly superceeds manual actions described below.

# PREREQUISITES

## RedHat 6, 7, 8:
```
sudo yum install cmake gcc gcc-c++ openssl openssl-devel wget
```
For RedHat/CentOS version 6 follow the steps (https://edwards.sdsu.edu/research/c11-on-centos-6/) to be able to compile C++11:
```
sudo wget http://people.centos.org/tru/devtools-2/devtools-2.repo -O /etc/yum.repos.d/devtools-2.repo
sudo yum upgrade
sudo yum install devtoolset-2-gcc devtoolset-2-binutils devtoolset-2-gcc-c++
scl enable devtoolset-2 bash
```
### Check gcc version:
```
gcc --version
```
Should be at least 4.8.2.

## Debian/Ubuntu:
```
sudo apt-get install cmake gcc g++ openssl libssl-dev
```
## COMMON for RedHat and Debian/Ubuntu

ℹ consider using `checkinstall` ( https://wiki.debian.org/CheckInstall ) on Debian/Ubuntu for putting protobuf and boost into packages, so you can easily manage it later!

### Install Google protobuf v3.6.1 or later

#### common way
```
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protobuf-cpp-3.6.1.tar.gz && \
tar -xzf protobuf-cpp-3.6.1.tar.gz && cd protobuf-3.6.1 && ./configure && time make -j 4
make install
sudo ldconfig
```

#### checkinstall way packaging - use call to `checkinstall` instead of `make install`

```
sudo checkinstall --install=no make install
sudo dpkg -i protobuf_3.6.1-1_amd64.deb
sudo ldconfig
```

### Install boost libraries v1.69.0 or later

boost - we need version 1.66 and in the repo there is 1.53 (for redhat 7)
#### common way
```
wget https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz && \
tar -xzf boost_1_69_0.tar.gz && cd boost_1_69_0
./bootstrap.sh
./b2 -j 4
sudo ./b2 install
```
#### checkinstall way packaging - use call to `checkinstall` instead of `./b2 install`

```
wget https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz && \
tar -xzf boost_1_69_0.tar.gz && cd boost_1_69_0
./bootstrap.sh
./b2 -j 4
sudo checkinstall --install=no ./b2 install
```

then install with `sudo dpkg -i boost-1-69-0_20200708-1_amd64.deb`
### Check cmake version: 
```
cmake --version
```
If it's lower than 3.9 then update it:
```
sudo apt remove cmake
wget https://github.com/Kitware/CMake/releases/download/v3.14.3/cmake-3.14.3.tar.gz
tar -xzf cmake-3.14.3.tar.gz
cd cmake-3.14.3
./bootstrap
make -j 4
sudo make install
```

### Copy project directories: nectus-agent/, Common/ and 3rdParty/.

### Compile protobuf file:
```
cd Common
protoc --cpp_out=. monitoring.proto
```
### Compile the project:
```
cd nectus-agent
// If a new version is created then update main.cpp/agentVersion string
cmake .
make -j 4
strip ./nectus-agent
```