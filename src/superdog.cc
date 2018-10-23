/****************************************************************************
*
* Demo program for SuperDog license detect
*
* Copyright (C) 2012 SafeNet, Inc. All rights reserved.
*
****************************************************************************/
// hello.cc
#include <node.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <windows.h> 

#include "dog_api.h"
#include "dog_vcode.h"
#include "encryption_array1.h" 
#include "encrypted_const1.h"
#include "encrypted_string1.h"

#define DUMP_COLS_PER_ROW     16
#define DUMP_SPACE_COLS        8

#define CUSTOM_FEATURE 0
#define CUSTOM_FILEID  DOG_FILEID_RO
#define DEMO_MEMBUFFER_SIZE   36

unsigned char membuffer[DEMO_MEMBUFFER_SIZE];

#define SAFE_FREE(p) { if(p) { free(p); (p) = NULL; } }

#ifdef _WIN64 //64位
    #pragma comment(lib, "../vendor/libdog_windows_x64_demo.lib")
#else //32位
    #pragma comment(lib, "../vendor/libdog_windows_demo.lib")
#endif

#pragma comment(lib, "legacy_stdio_definitions.lib")


dog_status_t CheckKey();
dog_status_t DecryptConst();
dog_status_t DecryptString();
dog_status_t ReadData(char*);

ENCRYPT_DATA_TYPE1 getConstValue(unsigned char *bufdata);
void getStringValue(unsigned char *bufData);
void dump(unsigned char *data, unsigned int datalen, char *margin);
void dump_ascii(unsigned char *data, unsigned int datalen, char *margin);
void dump_hex(unsigned char *data, unsigned int datalen, char *margin);


#include <node.h>

namespace superdog {

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

void Method(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  //char* UserId[] = new char[36];
  unsigned char UserId[DEMO_MEMBUFFER_SIZE];
  memset(UserId, 0, ENCRYPT_BUFFER_LENGTH1+1);
  ReadData((char*)&UserId);
  args.GetReturnValue().Set(String::NewFromUtf8(isolate, (char*)UserId));
}

void Initialize(Local<Object> exports) {
  NODE_SET_METHOD(exports, "getUserId", Method);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)

}  // namespace demo

int main()
{
	printf("\nA simple demo program for the SuperDog licensing functions\n");
	printf("Copyright (C) SafeNet, Inc. All rights reserved.\n\n");

	//check key using encryption array
	dog_status_t   status = CheckKey();

	//decrypt constant using SuperDog
	DecryptConst();

	//decrypt string or raw data using SuperDog
	DecryptString();

	printf("\n\n");

	//ReadData();

	return 0;
}

dog_status_t CheckKey()
{
	dog_status_t   status;
	dog_handle_t   hDog;	 
	
	unsigned char *bufData = NULL; 
	int nStatus   = 0;  
	int i, j;
	i = j = 0;
	
	/************************************************************************
	* dog_login
	*   establishes a context for SuperDog
	*/
	status = dog_login(GENARR_FEATUREID1,       
		vendor_code,	
		&hDog);   
	if (DOG_STATUS_OK != status) 
	{
		switch (status)
		{  
        case DOG_INV_VCODE:
            printf("Invalid vendor code.\n");
            break;
			
		case DOG_UNKNOWN_VCODE:
            printf("Vendor Code not recognized by API.\n");
            break;
			
        default:
            printf("Login to feature: %d failed with status %d\n", GENARR_FEATUREID1, status );
		} 
		return status; 
	}    
	
	srand( (unsigned)time( NULL ) );
	
	bufData = (unsigned char *)malloc(ENCRYPTDATA_LEN1);
	memset(bufData, 0, ENCRYPTDATA_LEN1);
	
	//Generate a random index number
	i = rand() % GENERATE_COUNT1; 
	memcpy(bufData,encryptionArray1[i][0],ENCRYPTDATA_LEN1);  
	
	/*
	* dog_encrypt
	*   encrypts a block of data using SuperDog
	*   (minimum buffer size is 16 bytes)
	*/
	status = dog_encrypt(hDog, bufData, ENCRYPTDATA_LEN1);  
	if (DOG_STATUS_OK != status) 
	{ 
		SAFE_FREE(bufData);
		dog_logout(hDog);  
		return status;
	}
	
	//Check the encrypted data is right or wrong
	for(j = 0; j < ENCRYPTDATA_LEN1; ++j)
	{
		if(bufData[j] ^ encryptionArray1[i][1][j])
		{
			printf( "Encrypted data is wrong.\n" );      
			SAFE_FREE(bufData);
			dog_logout(hDog);   
			//return -1;
            return DOG_MEM_RANGE; 
		}
	}
	
	SAFE_FREE(bufData);
	dog_logout(hDog);  
	
	printf( "Check Dog using encryption array success.\n" );  
	
	return DOG_STATUS_OK; 
}

dog_status_t DecryptConst()
{
	dog_status_t   status;
	dog_handle_t   hDog;	 
	int nStatus   = 0;  
	int i = 0;
	unsigned char *bufData = NULL;  
	
	/************************************************************************
	* dog_login
	*   establishes a context for SuperDog
	*/
	status = dog_login(ENCRYPT_CONST_FEATUREID1,       
		vendor_code,	
		&hDog);   
	if (DOG_STATUS_OK != status) 
	{ 
		switch (status)
		{  
        case DOG_INV_VCODE:
            printf("Invalid vendor code.\n");
            break;
			
		case DOG_UNKNOWN_VCODE:
            printf("Vendor Code not recognized by API.\n");
            break;
			
        default:
            printf("Login to feature: %d failed with status %d\n", ENCRYPT_CONST_FEATUREID1, status );
		} 
		return status; 
	}    
	
	bufData = (unsigned char *)malloc(ENCRYPT_CONST_BUFSIZE1);
	memset(bufData, 0, ENCRYPT_CONST_BUFSIZE1); 
	memcpy(bufData,encryptConstArr1,ENCRYPT_CONST_BUFSIZE1);  
	
	/*
	* dog_decrypt
	*   decrypts a block of data which is encrypted
	*   (minimum buffer size is 16 bytes)
	*/
	status = dog_decrypt(hDog, bufData, ENCRYPT_CONST_BUFSIZE1);  
	if (DOG_STATUS_OK != status) 
	{ 
		SAFE_FREE(bufData);
		dog_logout(hDog);  
		return status;
	}
	
	//Use the decrypted constants do some operation  
	g_constValue1 = getConstValue(bufData);
	
	PRINT_CONST_VALUE1(g_constValue1) 
		
	SAFE_FREE(bufData);
	dog_logout(hDog);   
	
	return status; 
}


dog_status_t DecryptString()
{
	dog_status_t   status;
	dog_handle_t   hDog;	 
	int nStatus   = 0;  
	int i = 0;
	unsigned char *bufData = NULL;   
	
	/************************************************************************
	* dog_login
	*   establishes a context for SuperDog
	*/
	status = dog_login(ENCRYPT_BUFFER_FEATUREID1,       
		vendor_code,	
		&hDog);   
	if (DOG_STATUS_OK != status) 
	{ 
		switch (status)
		{  
        case DOG_INV_VCODE:
            printf("Invalid vendor code.\n");
            break;
			
		case DOG_UNKNOWN_VCODE:
            printf("Vendor Code not recognized by API.\n");
            break;
			
        default:
            printf("Login to feature: %d failed with status %d\n", ENCRYPT_BUFFER_FEATUREID1, status );
		} 
		return status; 
	}    
	
	bufData = (unsigned char *)malloc(ENCRYPT_BUFFER_LENGTH1+1);
	memset(bufData, 0, ENCRYPT_BUFFER_LENGTH1+1); 
	memcpy(bufData, encryptStrArr1, ENCRYPT_BUFFER_LENGTH1);  
	
	/*
	* dog_decrypt
	*   decrypts a block of data which is encrypted
	*   (minimum buffer size is 16 bytes)
	*/
	status = dog_decrypt(hDog, bufData, ENCRYPT_BUFFER_LENGTH1);  
	if (DOG_STATUS_OK != status) 
	{ 
		SAFE_FREE(bufData);
		dog_logout(hDog);  
		return status;
	}
	
	//If source string length is less than 16, we need add 0 to the remained buffer
	if(ENCRYPT_BUFFER_LENGTH1 > SOURCE_BUFFER_LENGTH1)
	{ 
		memset(bufData+SOURCE_BUFFER_LENGTH1, 0, ENCRYPT_BUFFER_LENGTH1-SOURCE_BUFFER_LENGTH1);
	}  
	
	//Use the decrypted data do some operation    
	if(0 == isString1)
	{ 
		printf("The decrypted buffer data is below :\n"); 
		dump(bufData, SOURCE_BUFFER_LENGTH1, "    "); 
	}
	else
	{
		getStringValue(bufData);
		printf("The decrypted string is: \"%s\".\n", bufData); 
	}
	
	
	SAFE_FREE(bufData);
	dog_logout(hDog);   
	
	return status; 
}

dog_status_t ReadData(char* userid)
{
	dog_status_t   status;
	dog_handle_t   hDog;
	dog_time_t     time;
	unsigned int    day, month, year, hour, minute, second;

	char           *info;         /* pointer to key info data */
	dog_size_t     fsize;
	unsigned int    i;
	/************************************************************************
	* dog_login
	*   establishes a context for SuperDog
	*/
	status = dog_login(GENARR_FEATUREID1,
		vendor_code,
		&hDog);
	if (DOG_STATUS_OK != status)
	{
		switch (status)
		{
		case DOG_INV_VCODE:
			printf("Invalid vendor code.\n");
			break;

		case DOG_UNKNOWN_VCODE:
			printf("Vendor Code not recognized by API.\n");
			break;

		default:
			printf("Login to feature: %d failed with status %d\n", GENARR_FEATUREID1, status);
		}
		return status;
	}
	/************************************************************************
	* dog_get_size
	*   retrieve the file size of a data file
	*/

	//printf("\nretrieving data file size : ");

	status = dog_get_size(hDog,
		CUSTOM_FILEID,
		&fsize);

	switch (status)
	{
	case DOG_STATUS_OK:
		//printf("data file size is %d bytes\n", fsize);
		break;

	case DOG_INV_HND:
		printf("handle not active\n");
		break;

	case DOG_INV_FILEID:
		printf("invalid file id\n");
		break;

	case DOG_NOT_FOUND:
		printf("key/license container not available\n");
		break;

	default:
		printf("could not retrieve memory size\n");
	}
	if (status) {
		dog_logout(hDog);
		exit(-1);
	}

	if (fsize != 0)       /* skip memory access if no memory available */
	{

		/********************************************************************
		* dog_read
		*   read from data file
		*/

		/* limit memory size to be used in this demo program */

		if (fsize > DEMO_MEMBUFFER_SIZE)
			fsize = DEMO_MEMBUFFER_SIZE;

		//printf("\nreading %4d bytes from memory   : ", fsize);

		status = dog_read(hDog,
			CUSTOM_FILEID,     /* file ID */
			0,                 /* offset */
			fsize,             /* length */
			&membuffer[0]);    /* file data */

		switch (status)
		{
		case DOG_STATUS_OK:
			//printf("OK\n");
			//dump(membuffer, fsize, "    ");
            memcpy(userid,membuffer,36);
			break;

		case DOG_INV_HND:
			printf("handle not active\n");
			break;

		case DOG_INV_FILEID:
			printf("invalid file id\n");
			break;

		case DOG_MEM_RANGE:
			printf("exceeds data file range\n");
			break;

		case DOG_NOT_FOUND:
			printf("key/license container not available\n");
			break;

		default:
			printf("read memory failed\n");
		}
		if (status) {
			dog_logout(hDog);
			exit(-1);
		}
	}
}

ENCRYPT_DATA_TYPE1 getConstValue(unsigned char *bufdata)
{
	return *(ENCRYPT_DATA_TYPE1 *)bufdata;
}

void getStringValue(unsigned char *bufData)
{
	int wcsLen = 0;
	wchar_t* wszString = NULL; 
	int textlen = 0;
	
	//Change UTF8 format string to unicode   
	wcsLen = MultiByteToWideChar(CP_UTF8, 0, (const char*)bufData, ENCRYPT_BUFFER_LENGTH1, NULL, 0); 
	wszString = (wchar_t *)malloc( sizeof(wchar_t)*(wcsLen + 1) ); 
	MultiByteToWideChar(CP_UTF8, 0, (const char*)bufData, ENCRYPT_BUFFER_LENGTH1, wszString, wcsLen); 
	wszString[wcsLen] = '\0';

	//Change unicode string to ansi
	textlen = WideCharToMultiByte( CP_ACP, 0, wszString, -1, NULL, 0, NULL, NULL ); 
	WideCharToMultiByte( CP_ACP, 0, wszString, -1, (char*)bufData, textlen, NULL, NULL ); 
	
	SAFE_FREE(wszString);
}

/****************************************************************************
 * helper function: dumps a given block of data, in hex
 */

void dump_hex(unsigned char *data, unsigned int datalen, char *margin)
{
    unsigned int i;
	
    for (i = 0; i < datalen; i++)
    {
        if (((i % DUMP_SPACE_COLS) == 0) && (i != 0))
            printf(" ");
		
        if ((i % DUMP_COLS_PER_ROW) == 0)
        {
            if (i != 0)
                printf("\n");
			
            if (margin != NULL)
                printf("%s", margin);
        }
		
        /* dump character in hex */
        printf("%02X ", data[i]);
    }
} /* dump_hex */

/****************************************************************************
 * helper function: dumps a given block of data, in ascii
 */

void dump_ascii(unsigned char *data, unsigned int datalen, char *margin)
{
    unsigned int i;
	
    for (i = 0; i < datalen; i++)
    {
        if (((i % DUMP_SPACE_COLS) == 0) && (i != 0))
            printf(" ");
		
        if ((i % DUMP_COLS_PER_ROW) == 0)
        {
            if (i != 0)
                printf("\n");
			
            if (margin != NULL)
                printf("%s", margin);
        }
		
        /* dump printable character in ascii */
        printf("%c", ((data[i] > 31) && (data[i] < 128)) ? data[i] : '.');
    }
} /* dump_ascii */

/****************************************************************************
 * helper function: dumps a given block of data, in hex and ascii
 */

void dump(unsigned char *data, unsigned int datalen, char *margin)
{
    unsigned int i, icols;
	
    for (i = 0; i < datalen; )
    {
        icols = datalen - i;
		
        if (icols > DUMP_COLS_PER_ROW)
            icols = DUMP_COLS_PER_ROW;
		
        dump_hex(&data[i], icols, margin);
        dump_ascii(&data[i], icols, "  ");
        printf("\n");
		
        i += icols;
    }
} /* dump */
	