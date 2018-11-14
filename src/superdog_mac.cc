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
#include "encryption_array1.h" 
#include "encrypted_string1.h"
#define ENCRYPT_CONST_FEATUREID1 0    //feature id which is selected
#define ENCRYPT_CONST_BUFSIZE1 16    //Size of encrypt constants


#define DUMP_COLS_PER_ROW     16
#define DUMP_SPACE_COLS        8

#define CUSTOM_FEATURE 0
#define CUSTOM_FILEID  DOG_FILEID_RO
#define DEMO_MEMBUFFER_SIZE   36

unsigned char membuffer[DEMO_MEMBUFFER_SIZE];

#define SAFE_FREE(p) { if(p) { free(p); (p) = NULL; } }


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
  unsigned char UserId[DEMO_MEMBUFFER_SIZE+1];
  memset(UserId, 0, ENCRYPT_BUFFER_LENGTH1+1);
//  ReadData((char*)&UserId);
  memset(UserId,0,sizeof(UserId));
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
	return 0;
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


