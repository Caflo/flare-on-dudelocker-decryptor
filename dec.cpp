#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <ctype.h>
#include <conio.h>
#include <iterator>
#include <iostream>
#include <typeinfo>

#define MD5LEN 16

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define ENCRYPT_BLOCK_SIZE 8 

using namespace std;

bool MyDecryptFile(
    LPTSTR szSource, 
    LPTSTR szDestination, 
    LPTSTR szPassword, 
    LPTSTR szPlainIv);

void MyHandleError(
    LPTSTR psz, 
    int nErrorNumber);

int _tmain(int argc, _TCHAR* argv[])
{
    if(argc < 4)
    {
        _tprintf(TEXT("Usage: <dec.exe> <source file> ")
            TEXT("<destination file>  <password>\n"));
        _tprintf(TEXT("Press any key to exit."));
        getch();
        return 1;
    }

    LPTSTR pszSource = argv[1]; 
    LPTSTR pszDestination = argv[2]; 
    LPTSTR plain_iv = argv[3]; 

    TCHAR * pw = _T("thosefilesreallytiedthefoldertogether");
    LPTSTR pszPassword = pw;

    //---------------------------------------------------------------
    // Call EncryptFile to do the actual encryption.
    if(MyDecryptFile(pszSource, pszDestination, pszPassword, plain_iv))
    {
        _tprintf(
            TEXT("Decryption of the file %s was successful. \n"), 
            pszSource);
        _tprintf(
            TEXT("The decrypted data is in file %s.\n"), 
            pszDestination);
    }
    else
    {
        MyHandleError(
            TEXT("Error decrypting file!\n"), 
            GetLastError()); 
    }

    return 0;
}

//-------------------------------------------------------------------
// Code for the function MyDecryptFile called by main.
//-------------------------------------------------------------------
// Parameters passed are:
//  pszSource, the name of the input file, an encrypted file.
//  pszDestination, the name of the output, a plaintext file to be 
//   created.
//  pszPassword, either NULL if a password is not to be used or the 
//   string that is the password.
bool MyDecryptFile(
    LPTSTR pszSourceFile, 
    LPTSTR pszDestinationFile, 
    LPTSTR pszPassword, 
    LPTSTR plainIv)
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

    DWORD dwCount;
    PBYTE pbBuffer = NULL; 
    DWORD dwBlockLen; 
    DWORD dwBufferLen; 

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
            TEXT("The source encrypted file, %s, is open. \n"), 
            pszSourceFile);
    }
    else
    { 
        MyHandleError(
            TEXT("Error opening source plaintext file!\n"), 
            GetLastError());
        goto Exit_MyDecryptFile;
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
        goto Exit_MyDecryptFile;
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
        goto Exit_MyDecryptFile;
    }

    //-----------------------------------------------------------
    // Decrypt the file with a session key derived from a 
    // password. 




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
        goto Exit_MyDecryptFile;
    }
    
    //-----------------------------------------------------------
    // Hash in the password data. 
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
        goto Exit_MyDecryptFile;
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
        goto Exit_MyDecryptFile;
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
        goto Exit_MyDecryptFile;
    }

    //---------------------------------------------------------------
    // The decryption key is now available, either having been 
    // imported from a BLOB read in from the source file or having 
    // been created by using the password. This point in the program 
    // is not reached if the decryption key is not available.
     
    //---------------------------------------------------------------
    // Determine the number of bytes to decrypt at a time. 
    // This must be a multiple of ENCRYPT_BLOCK_SIZE. 

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 
    dwBufferLen = dwBlockLen; 

    //---------------------------------------------------------------
    // Allocate memory for the file read buffer. 
    if(!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
    {
       MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY); 
       goto Exit_MyDecryptFile;
    }
    
    //---------------------------------------------------------------
    // Decrypt the source file, and write to the destination file. 
    bool fEOF = false;
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
                TEXT("Error reading from source file!\n"), 
                GetLastError());
            goto Exit_MyDecryptFile;
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
            goto Exit_MyDecryptFile;
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
            goto Exit_MyDecryptFile;
        }  

        //-----------------------------------------------------------
        // CryptHashData -> hash file content
        // pszSourceFile must be converted in lowercase before CryptHashData

        char *f = (char *)plainIv;
        // converting in lowercase
        for (int i = 0; f[i]; i++) {
            f[i] = tolower(f[i]);
        }

        BYTE * filename = (BYTE *)f;
        cout << filename << '\n';    
        cout << strlen(f) << '\n';    
    

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
            goto Exit_MyDecryptFile;
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
            goto Exit_MyDecryptFile;
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
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // CryptDestroyHash -> destroy hash stored in memory
        // placeholder

        //-----------------------------------------------------------
        // Decrypt the block of data. 
//        if(!CryptDecrypt(
//              hKey_AES, 
//              0, 
//              fEOF, 
//              0, 
//              pbBuffer, 
//              &dwCount))
//        {
//            MyHandleError(
//                TEXT("Error during CryptDecrypt!\n"), 
//                GetLastError()); 
//            goto Exit_MyDecryptFile;
//        }

        // invoking CryptDecrypt in the if clause seems to makes it fail. The problem only is when 
        // businesspapers.doc file is given as file to decrypt. For all the other files the code works.
        CryptDecrypt(hKey_AES, 0, fEOF, 0, pbBuffer, &dwCount);

        //-----------------------------------------------------------
        // Write the decrypted data to the destination file. 
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
            goto Exit_MyDecryptFile;
        }

        //-----------------------------------------------------------
        // End the do loop when the last block of the source file 
        // has been read, encrypted, and written to the destination 
        // file.
    }while(!fEOF);

    fReturn = true;

Exit_MyDecryptFile:

    //---------------------------------------------------------------
    // Free the file read buffer.
    if(pbBuffer)
    {
        free(pbBuffer);
    }

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
}


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