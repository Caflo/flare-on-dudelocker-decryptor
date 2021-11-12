# flare-on-dudelocker-decryptor
This repo contains the decryptor for the Flare-On 2016 challenge 2 "Dudelocker". Important note must be read in dec.cpp to adjust code in case the decryptor doesn't work for your file.
<br>There's also an encryptor just for fun (:

# compiling
using g++:
```console
g++ -fpermissive -Wwrite-strings .\dec.cpp -o .\dec.exe -w
```

# example usage:
```console
.\dec.exe ".\SampleFiles\BusinessPapers.doc" "output.jpg" "businesspapers.doc"
```
where 
- ".\SampleFiles\BusinessPapers.doc" is the encrypted source file
- "output.jpg" is the path of the result of the decryption 
- "businesspapers.doc" is the plaintext initialization vector used in the MD5 hashing. For this challenge, it's always the filename + extension in lowercase.
