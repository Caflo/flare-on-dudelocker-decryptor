# flare-on-dudelocker-decryptor
This repo contains the decryptor for the Flare-On 2016 challenge 2 "Dudelocker". There's also an encryptor just for fun (:

# compiling
using g++:
g++ -fpermissive -Wwrite-strings .\dec.cpp -o .\dec.exe -w

# example usage:
.\dec.exe "path\to\BusinessPapers.doc" "output.jpg" "businesspapers.doc"
where "BusinessPapers.doc" is the source file encrypted; "output.jpg" is the result of the decryption; "businesspapers.doc" is the plaintext initialization vector used in the MD5 hashing.
