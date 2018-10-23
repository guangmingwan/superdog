//    Source data: 123456789

#define ENCRYPT_CONST_FEATUREID1 0    //feature id which is selected
#define ENCRYPT_CONST_BUFSIZE1 16    //Size of encrypt constants
#define PRINT_CONST_VALUE1(p) {printf("The decrypted value is: %d.\n", p);}

typedef __int32 ENCRYPT_DATA_TYPE1;
ENCRYPT_DATA_TYPE1 g_constValue1;

unsigned char encryptConstArr1[16] = { 
   0x1C, 0x03, 0xBD, 0xF9, 0x27, 0xCF, 0x5C, 0xE6, 0x3D, 0x5B, 0xF1, 0x2F, 0xEF, 0x2F, 0x5B, 0x5A
 };
