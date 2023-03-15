# suci
5G SUCI computation on UE using wolfSSL . For moire information on suci please check this link. https://www.discreteworks.com/transform/2022/05/08/suci-computation-on-ue.html

[![Build Status](https://api.cirrus-ci.com/github/discreteworks/suci.svg)](https://cirrus-ci.com/github/discreteworks/suci)

## wolfSSL build instructions
```
cd wolfSSL
./autogen.sh
./configure --enable-curve25519 --enable-eccencrypt --enable-aesctr --enable-x963kdf --enable-compkey
make -j$(nproc)
sudo make install
```

## SUCI computation on UE build and run instructions
```
cd suci
mkdir build
cd build
cmake ..
make -j$(nproc)

# for dynamic linking
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/lib"

# run
./suci

```

## Docker
```
docker run -ti munfasil/wolfssl /bin/bash
git clone https://github.com/discreteworks/suci.git
cd suci
mkdir build
cd build
cmake ..
make -j$(nproc)
```
