#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <libgen.h>
#include <ctype.h>
#include <wincrypt.h>
#include <conio.h>
#include <string.h>
#include <iterator>
#include <iostream>
#include <typeinfo>

#define MD5LEN 16

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define ENCRYPT_BLOCK_SIZE 8 

using namespace std;

bool MyEncryptFile(
    LPTSTR szSource, 
    LPTSTR szDestination, 
    LPTSTR szPassword);

void MyHandleError(
    LPTSTR psz, 
    int nErrorNumber);

int _tmain(int argc, _TCHAR* argv[])
{
    if(argc < 3)
    {
        _tprintf(TEXT("Usage: <example.exe> <source file> ")
            TEXT("<destination file> \n"));
        _tprintf(TEXT("Press any key to exit."));
        getch();
        return 1;
    }

    LPTSTR pszSource = argv[1]; 
    LPTSTR pszDestination = argv[2]; 

    TCHAR * pw = _T("thosefilesreallytiedthefoldertogether");
    LPTSTR pszPassword = pw;

    //---------------------------------------------------------------
    // Call EncryptFile to do the actual encryption.
    if(MyEncryptFile(pszSource, pszDestination, pszPassword))
    {
        _tprintf(
            TEXT("Encryption of the file %s was successful. \n"), 
            pszSource);
        _tprintf(
            TEXT("The encrypted data is in file %s.\n"), 
            pszDestination);
    }
    else
    {
        MyHandleError(
            TEXT("Error encrypting file!\n"), 
            GetLastError()); 
    }

    return 0;
}

//-------------------------------------------------------------------
// Code for the function MyEncryptFile called by main.
//-------------------------------------------------------------------
// Parameters passed are:
//  pszSource, the name of the input, a plaintext file.
//  pszDestination, the name of the output, an encrypted file to be 
//   created.
//  pszPassword, either NULL if a password is not to be used or the 
//   string that is the password.
bool MyEncryptFile(
    LPTSTR pszSourceFile, 
    LPTSTR pszDestinationFile, 
    LPTSTR pszPassword)
{ 
    //---------------------------------------------------------------
    // Declare and initialize local variables.
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE; 

    HCRYPTPROV hCryptProv = NULL; 
    HCRYPTKEY hKey_AES = NULL; 
    HCRYPTHASH hHash_SHA1 = NULL; 
    HCRYPTHASH hHash_MD5 = NULL; 

    PBYTE pbBuffer = NULL; 
    DWORD dwBlockLen; 
    DWORD dwBufferLen; 
    DWORD dwCount; 
     
    //---------------------------------------------------------------
    // Open the source file. 
    hSourceFile = CreateFile(
        pszSourceFile, 
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if(INVALID_HANDLE_VALUE != hSourceFile)
    {
        _tprintf(
            TEXT("The source plaintext file, %s, is open. \n"), 
            pszSourceFile);
    }
    else
    { 
        MyHandleError(
            TEXT("Error opening source plaintext file!\n"), 
            GetLastError());
        goto Exit_MyEncryptFile;
    } 

    //---------------------------------------------------------------
    // Open the destination file. 
    hDestinationFile = CreateFile(
        pszDestinationFile, 
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if(INVALID_HANDLE_VALUE != hDestinationFile)
    {
         _tprintf(
             TEXT("The destination file, %s, is open. \n"), 
             pszDestinationFile);
    }
    else
    {
        MyHandleError(
            TEXT("Error opening destination file!\n"), 
            GetLastError()); 
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Get the handle to the default provider. 
    if(CryptAcquireContextW(
        &hCryptProv, 
        0, 
        0, 
        PROV_RSA_AES,
        0))
    {
        _tprintf(
            TEXT("A cryptographic provider has been acquired. \n"));
    }
    else
    {
        MyHandleError(
            TEXT("Error during CryptAcquireContext!\n"), 
            GetLastError());
        goto Exit_MyEncryptFile;
    }

    //-----------------------------------------------------------
    // The file will be encrypted with a session key derived 
    // from a password.
    // The session key will be recreated when the file is 
    // decrypted only if the password used to create the key is 
    // available. 

    //-----------------------------------------------------------
    // Create a hash object. 
    if(CryptCreateHash(
        hCryptProv, 
        CALG_SHA1,
        0, 
        0, 
        &hHash_SHA1))
    {
        _tprintf(TEXT("A hash object has been created. \n"));
    }
    else
    { 
        MyHandleError(
            TEXT("Error during CryptCreateHash!\n"), 
            GetLastError());
        goto Exit_MyEncryptFile;
    }  

    //-----------------------------------------------------------
    // Hash the password. 
    if(CryptHashData(
        hHash_SHA1, 
        (BYTE *)pszPassword, 
        37,
        0))
    {
        _tprintf(
            TEXT("The password has been added to the hash. \n"));
    }
    else
    {
        MyHandleError(
            TEXT("Error during CryptHashData. \n"), 
            GetLastError()); 
        goto Exit_MyEncryptFile;
    }

    //-----------------------------------------------------------
    // Derive a session key from the hash object. 
    if(CryptDeriveKey(
        hCryptProv, 
        CALG_AES_256, 
        hHash_SHA1, 
        1,
        &hKey_AES))
    {
        _tprintf(
            TEXT("An encryption key is derived from the ")
                TEXT("password hash. \n")); 
    }
    else
    {
        MyHandleError(
            TEXT("Error during CryptDeriveKey!\n"), 
            GetLastError()); 
        goto Exit_MyEncryptFile;
    }

    // Set AES in CBC mode
    DWORD crypt_mode = CRYPT_MODE_CBC;
    if (CryptSetKeyParam( 
        hKey_AES,                
        KP_MODE, 
        (BYTE *)&crypt_mode,
        0
    ))
    {
            _tprintf(
                TEXT("Key parameters set (AES_ECB). \n"));
    }
    else
    {
        printf("Error in CryptSetKeyParam 0x%08x (SET AES_CBC MODE)\n", 
        GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // The session key is now ready. If it is not a key derived from 
    // a password, the session key encrypted with the private key 
    // has been written to the destination file.
     
    //---------------------------------------------------------------
    // Determine the number of bytes to encrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE.
    // ENCRYPT_BLOCK_SIZE is set by a #define statement.

    // IMPORTANT note at this line in dec.cpp
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

    //---------------------------------------------------------------
    // Determine the block size. If a block cipher is used, 
    // it must have room for an extra block. 
    if(ENCRYPT_BLOCK_SIZE > 1) 
    {
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
    }
    else 
    {
        dwBufferLen = dwBlockLen; 
    }
        
    //---------------------------------------------------------------
    // Allocate memory. 
    if(pbBuffer = (BYTE *)malloc(dwBufferLen))
    {
        _tprintf(
            TEXT("Memory has been allocated for the buffer. \n"));
    }
    else
    { 
        MyHandleError(TEXT("Out of memory. \n"), E_OUTOFMEMORY); 
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // In a do loop, encrypt the source file, 
    // and write to the source file. 
    bool fEOF = FALSE;
    do 
    { 
        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file. 
        if(!ReadFile(
            hSourceFile, 
            pbBuffer, 
            dwBlockLen, 
            &dwCount, 
            NULL))
        {
            MyHandleError(
                TEXT("Error reading plaintext!\n"), 
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        if(dwCount < dwBlockLen)
        {
            fEOF = TRUE;
        }

        //-----------------------------------------------------------
        // CryptGetKeyParam -> retrieves created key 

        LPTSTR buf = NULL;
        DWORD buflen = 4;
        if(CryptGetKeyParam( // get size of the key (dwparam = 8)
            hKey_AES, 
            8, 
            (BYTE *) buf, //(BYTE *)buf,  // pbBuffer
            &buflen,  // dwBufferLen
            0 // dwFlags
        )) 
        {
            _tprintf(TEXT("A hash object has been created. \n"));
        }
        else
        { 
            MyHandleError(
                TEXT("Error during CryptGetKeyParam!\n"), 
                GetLastError());
            goto Exit_MyEncryptFile;
        }  

        //-----------------------------------------------------------
        // CryptCreateHash -> create MD5 hash from filename

        if(CryptCreateHash(
                hCryptProv, 
                CALG_MD5,
                0, 
                0, 
                &hHash_MD5
        ))
        {
            _tprintf(TEXT("A hash object has been created. \n"));
        }
        else
        { 
            MyHandleError(
                TEXT("Error during CryptCreateHash (MD5)!\n"), 
                GetLastError());
            goto Exit_MyEncryptFile;
        }  

        //-----------------------------------------------------------
        // CryptHashData -> hash file content

        char *f = basename(pszSourceFile); // extracting filename from absolute path

        // converting in lowercase
        for (int i = 0; f[i]; i++) {
            f[i] = tolower(f[i]);
        }

        cout << "Hashing \"" << (BYTE *)f << "\" as plain IV \n";    

        // Hash the password. 
        if(CryptHashData(
            hHash_MD5, 
            (BYTE *)f, 
            strlen(f), 
            0
        ))
        {
            _tprintf(
                TEXT("The password has been added to the hash. \n"));
        }
        else
        {
            MyHandleError(
                TEXT("Error during CryptHashData. \n"), 
                GetLastError()); 
            goto Exit_MyEncryptFile;
        }


        //-----------------------------------------------------------
        // CryptGetHashParam -> retrieves hash parameters

        DWORD hashlen = MD5LEN; // 16
        BYTE hHash_MD5_val[16];
        DWORD dwParam = HP_HASHVAL;
        if (CryptGetHashParam(
            hHash_MD5,               
            HP_HASHVAL, 
            hHash_MD5_val,
            &hashlen,        
            0
        ))
        {
             _tprintf(
                 TEXT("Hash parameters retrieved. \n"));
        }
        else
        {
            printf("Error in CryptGetHashParam 0x%08x \n", 
            GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // CryptSetKeyParam -> set key parameter

        dwParam = KP_IV;
        if (CryptSetKeyParam( 
            hKey_AES,                
            KP_IV, 
            (BYTE *)hHash_MD5_val, 
            0
        ))
        {
             _tprintf(
                 TEXT("Key parameters set. (MD5) \n"));
        }
        else
        {
            printf("Error in CryptSetKeyParam 0x%08x (MD5) \n", 
            GetLastError());
            goto Exit_MyEncryptFile;
        }


        //-----------------------------------------------------------
        // CryptDestroyHash -> destroy hash stored in memory
        // placeholder


        //-----------------------------------------------------------
        // Encrypt data. 
        if(!CryptEncrypt(
            hKey_AES, 
            0, 
            fEOF, 
            0, 
            pbBuffer, 
            &dwCount, 
            dwBufferLen 
        ))
        { 
            MyHandleError(
                TEXT("Error during CryptEncrypt. \n"), 
                GetLastError()); 
            goto Exit_MyEncryptFile;
        } 
//        CryptEncrypt(hKey_AES, 0, FALSE, 0, pbBuffer, &dwCount, dwBufferLen);


        //-----------------------------------------------------------
        // Write the encrypted data to the destination file. 
        if(!WriteFile(
            hDestinationFile, 
            pbBuffer, 
            dwCount,
            &dwCount,
            NULL))
        { 
            MyHandleError(
                TEXT("Error writing ciphertext.\n"), 
                GetLastError());
            goto Exit_MyEncryptFile;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    } while(!fEOF);

    fReturn = true;

Exit_MyEncryptFile:
    //---------------------------------------------------------------
    // Close files.
    if(hSourceFile)
    {
        CloseHandle(hSourceFile);
    }

    if(hDestinationFile)
    {
        CloseHandle(hDestinationFile);
    }

    //---------------------------------------------------------------
    // Free memory. 
    if(pbBuffer) 
    {
        free(pbBuffer); 
    }
     

    //-----------------------------------------------------------
    // Release the hash object. 
    if(hHash_SHA1) 
    {
        if(!(CryptDestroyHash(hHash_SHA1)))
        {
            MyHandleError(
                TEXT("Error during CryptDestroyHash.\n"), 
                GetLastError()); 
        }

        hHash_SHA1 = NULL;
    }

    //---------------------------------------------------------------
    // Release the session key. 
    if(hKey_AES)
    {
        if(!(CryptDestroyKey(hKey_AES)))
        {
            MyHandleError(
                TEXT("Error during CryptDestroyKey!\n"), 
                GetLastError());
        }
    }

    //---------------------------------------------------------------
    // Release the provider handle. 
    if(hCryptProv)
    {
        if(!(CryptReleaseContext(hCryptProv, 0)))
        {
            MyHandleError(
                TEXT("Error during CryptReleaseContext!\n"), 
                GetLastError());
        }
    }
    
    return fReturn; 
} // End Encryptfile.


//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(LPTSTR psz, int nErrorNumber)
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}