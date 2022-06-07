# suci
5G SUCI computation on UE using wolfSSL

## wolfSSL build instructions
```
./autogen.sh
./configure --enable-curve25519 --enable-eccencrypt --enable-aesctr --enable-x963kdf --enable-compkey
make -j$(nproc)
sudo make install
```

### suci compute build and run instructions
```
mkdir build
cd build
cmake ..
make -j$(nproc)

# for dynamic linking
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/lib"

# run
./suci

```
