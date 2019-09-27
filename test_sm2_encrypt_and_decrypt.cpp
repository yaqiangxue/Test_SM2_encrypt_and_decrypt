/**************************************************
* File name: test_sm2_encrypt_and_decrypt.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Dec 9th, 2018
* Description: implement SM2 encrypt data and decrypt
    ciphertext test functions
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <sys/time.h> 
#include <unistd.h>
using namespace std;
#include "sm2_cipher_error_codes.h"
#include "sm2_create_key_pair.h"
#include "sm2_encrypt_and_decrypt.h"
#include "test_sm2_encrypt_and_decrypt.h"

/*********************************************************/
int test_with_input_defined_in_standard_old(void)
{
	int error_code;
	unsigned char msg[] = {"encryption standard"};
	int msg_len = (int)(strlen((char *)msg));
	unsigned char pub_key[] = {0x04, 0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1,
	                                 0x50, 0xdd, 0x7d, 0x16, 0x1e, 0x4b, 0xc5, 0xc6,
					 0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07,
					 0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3, 0x50, 0x20,
					 0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5,
					 0x2d, 0xc6, 0xea, 0x71, 0x8c, 0xc1, 0xaa, 0x60,
					 0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08, 0x4a,
					 0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 0xad, 0x13};
	unsigned char pri_key[32] = {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1,
	                             0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
	                             0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a,
	                             0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};
	unsigned char std_c1[65] = {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98,
	                                  0x62, 0x04, 0x32, 0x26, 0x8e, 0x77, 0xfe, 0xb6,
					  0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07, 0x3c, 0x0f,
					  0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73,
					  0xe8, 0x58, 0xf9, 0xd8, 0x1e, 0x54, 0x30, 0xa5,
					  0x7b, 0x36, 0xda, 0xab, 0x8f, 0x95, 0x0a, 0x3c,
					  0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d, 0x99,
					  0x28, 0x3a, 0xff, 0x76, 0x7e, 0x12, 0x4d, 0xf0};
	unsigned char std_c3[32] = {0x59, 0x98, 0x3c, 0x18, 0xf8, 0x09, 0xe2, 0x62,
	                            0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x03,
				    0x83, 0xb5, 0x4e, 0x39, 0xd6, 0x09, 0xd1, 0x60,
				    0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87, 0x66};
	unsigned char std_c2[19] = {0x21, 0x88, 0x6c, 0xa9, 0x89, 0xca, 0x9c, 0x7d,
	                            0x58, 0x08, 0x73, 0x07, 0xca, 0x93, 0x09, 0x2d,
				    0x65, 0x1e, 0xfa};
	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt_data_test(msg,
	                                        msg_len,
						pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext by using input defined in standard failed!\n");
		free(c2);
		return error_code;
	}

	if ( memcmp(c1, std_c1, sizeof(std_c1)) )
	{
		printf("C1 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}
	if ( memcmp(c3, std_c3, sizeof(std_c3)) )
	{
		printf("C3 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}
	if ( memcmp(c2, std_c2, sizeof(std_c2)) )
	{
		printf("C2 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}

	printf("Create SM2 ciphertext by using input defined in standard succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(std_c1); i++)
	{
		printf("0x%x  ", c1[i]);
	}
	printf("\n\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(std_c3); i++)
	{
		printf("0x%x  ", c3[i]);
	}
	printf("\n\n");
	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);
	printf("C2 component:\n");
	for (i = 0; i < sizeof(std_c2); i++)
	{
		printf("0x%x  ", c2[i]);
	}
	printf("\n\n");

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		                      c3,
				      c2,
				      msg_len,
				      pri_key,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext by using private key defined in standard failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext by using private key defined in standard succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}

/*********************************************************/
int test_sm2_encrypt_and_decrypt(void)
{
	int error_code;
	unsigned char msg[] = {"encryption standard"};
	int msg_len = (int)(strlen((char *)msg));
	SM2_KEY_PAIR key_pair;
	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	if ( error_code = sm2_create_key_pair(&key_pair) )
	{
		printf("Create SM2 key pair failed!\n");
		return (-1);
	}
	printf("Create SM2 key pair succeeded!\n");
	printf("Private key:\n");
	for (i = 0; i < sizeof(key_pair.pri_key); i++)
	{
		printf("0x%x  ", key_pair.pri_key[i]);
	}
	printf("\n\n");
	printf("Public key:\n");
	for (i = 0; i < sizeof(key_pair.pub_key); i++)
	{
		printf("0x%x  ", key_pair.pub_key[i]);
	}
	printf("\n\n");

	printf("/*********************************************************/\n");
	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt_data_test(msg,
	                                        msg_len,
						key_pair.pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext failed!\n");
		free(c2);
		return error_code;
	}

	printf("Create SM2 ciphertext succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(c1); i++)
	{
		printf("0x%x  ", c1[i]);
	}
	printf("\n\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(c3); i++)
	{
		printf("0x%x  ", c3[i]);
	}
	printf("\n\n");
	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);
	printf("C2 component:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", c2[i]);
	}
	printf("\n\n");

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		                      c3,
				      c2,
				      msg_len,
				      key_pair.pri_key,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}
// 将16进制的string字符串，转成16进制的arr
int hexCharStr2unsignedCharStr(char *src, unsigned long lsrc, int flag, unsigned char * out, unsigned long * lout)
{
	if((0 == flag && 0 !=lsrc%2) || (0 != flag && 0 !=lsrc%3) ||NULL == src || NULL == out )
	{
		if((0 == flag && 0 !=lsrc%2)){printf("珍珠包邮,lsrc = %d\n",lsrc);}
		if((0 != flag && 0 !=lsrc%3)){printf("镇住你嘛\n");}
		if(NULL == src){printf("空 \n");}
		if(NULL == out){printf("真 \n");}
		printf("fa kk 1 \n");
		return 1;//param err
	}
	
	int j = 0;//index of out buff
	if(0 == flag)
	{	//int i;
		for (int i=0; i<lsrc; i += 2)
		{
			int tmp = 0;
			int HIGH_HALF_BYTE = 0;
			int LOW_HALF_BYTE = 0;
			if (src[i]>= 0x30 && src[i]<=0x39)
			{
				HIGH_HALF_BYTE = src[i] - 0x30;
			}
			else if (src[i]>= 0x41 && src[i]<=0x46)
			{
				HIGH_HALF_BYTE = src[i] - 0x37;
			}
			else if( src[i]>= 0x61 && src[i]<=0x66)
			{
				HIGH_HALF_BYTE = src[i] - 0x57;
			}
			else if( src[i] == 0x20)
			{
				HIGH_HALF_BYTE = 0x00;
			}
			else
			{
				printf("fa kk 2 \n");
				return -1;
			}
			
			if (src[i+1]>= 0x30 && src[i+1]<=0x39)
			{
				LOW_HALF_BYTE = src[i+1] - 0x30;
			}
			else if (src[i+1]>= 0x41 && src[i+1]<=0x46)
			{
				LOW_HALF_BYTE = src[i+1] - 0x37;
			}
			else if( src[i+1]>= 0x61 && src[i+1]<=0x66)
			{
				LOW_HALF_BYTE = src[i+1] - 0x57;
			}
			else if( src[i+1] == 0x20)
			{
				LOW_HALF_BYTE = 0x00;
			}
			else
			{
				printf("fa kk 3 \n");
				return -1;
			}
			
			tmp = (HIGH_HALF_BYTE<<4) + LOW_HALF_BYTE;
			out [j] = tmp;
			j++;
		}
	}
	else
	{	//int i;
		for (int i=0; i<lsrc; i += 3)
		{
			int tmp = 0;
			int HIGH_HALF_BYTE = 0;
			int LOW_HALF_BYTE = 0;
			if ((i+2<= lsrc) && (src[i+2] != flag))
			{
				printf("fa kk 4 \n");
				return 1;
			}

			if (src[i]>= 0x30 && src[i]<=0x39 )
			{
				HIGH_HALF_BYTE = src[i] - 0x30;
			}
			else if (src[i]>= 0x41 && src[i]<=0x46)
			{
				HIGH_HALF_BYTE = src[i] - 0x37;
			}
			else if( src[i]>= 0x61 && src[i]<=0x66)
			{
				HIGH_HALF_BYTE = src[i] - 0x57;
			}
			else
			{
				printf("fa kk 5 \n");
				return -1;
			}
			
			if (src[i+1]>= 0x30 && src[i+1]<=0x39)
			{
				LOW_HALF_BYTE = src[i+1] - 0x30;
			}
			else if (src[i+1]>= 0x41 && src[i+1]<=0x46)
			{
				LOW_HALF_BYTE = src[i+1] - 0x37;
			}
			else if( src[i+1]>= 0x61 && src[i+1]<=0x66)
			{
				LOW_HALF_BYTE = src[i+1] - 0x57;
			}
			else
			{
				printf("fa kk 6 \n");
				return -1;
			}

			tmp = (HIGH_HALF_BYTE<<4) + LOW_HALF_BYTE;
			out [j] = tmp;
			j++;
		}
	}

	* lout = j;
	return 0;
	
}

// 将hexarr 转成16进制的字符串  如 0x11 0x22  转了之后是 “1122”
string array2hex(const unsigned char *arr, size_t len)
{
    size_t i;
    string res;
    char tmp[3];
    const char *tab = "0123456789ABCDEF";

    res.reserve(len * 2 + 1);
    for(i = 0; i < len; ++i) {
        tmp[0] = tab[arr[i] >> 4];
        tmp[1] = tab[arr[i] & 0xf];
        tmp[2] = '\0';
        res.append(tmp);
    }

    return res;
}
/*********************************************************/
// 这里我修改了一下。我的输出比较好看。上面那个我不想改了，麻烦死。
int test_with_input_defined_in_standard(double & vv)
{
	//Generated SM2 Private Key: [832B9C649C63B376DBD1D858C4D1B804CCFF6F7B6B588A9F30A54AF821F80E86]
    //               Public Key: [04FDFB7C93565AB39E1D8178429632EEC914F6A347AE9A0CE9B201FFAEA81A80CC4D81036191209B21CDBAD8A4BCD5C9A776FEDB771D6D2D8DAC0F1E5941C0F63C]
	struct timeval time1, time2; 
	gettimeofday(&time1, NULL);
	int error_code;
	unsigned char msg[] = {"aaaaa"};
	int msg_len = (int)(strlen((char *)msg));
	unsigned char buff[32] = {0}; // 私钥
	unsigned long buffLen = 32;
	unsigned char c1[65], c3[32];

	unsigned long c1Len = 65;
	unsigned long c3Len = 32;
	unsigned char *c2, *plaintext;
	unsigned long c2Len = 1024; // 弄得大一点，其实没啥
	int i;
	// 记住这里的公钥是加04的。不懂的话好好看看国密2 的pdf文档。
	char * pubkey_A_XY = "04FDFB7C93565AB39E1D8178429632EEC914F6A347AE9A0CE9B201FFAEA81A80CC4D81036191209B21CDBAD8A4BCD5C9A776FEDB771D6D2D8DAC0F1E5941C0F63C";
	char * myC1 = "11b6eb2d687e787652509fcbccc11d0bb48d0f8b73afbd7fdffaabf20d542b3cf8edace77d0b9b8c7d70c85c851fd190aee489d01a1e7f49a0c08588568a5f1b";
	char * myC2 = "73dd576a8f";
	char * myC3 = "bcd48b28507b668051c39e87c6be86656395439c1800dfc65c0045a8d9898adf";
	char * pri_key = "832B9C649C63B376DBD1D858C4D1B804CCFF6F7B6B588A9F30A54AF821F80E86";
	printf("... 准备工作...\n");
	printf("pri_key: %s .\n",pri_key);
	printf("myC1   : %s .\n",myC1);
	printf("myC2   : %s .\n",myC2);
	printf("myC3   : %s .\n",myC3);
	printf("msg    : %s .\n",msg);
	int b = hexCharStr2unsignedCharStr(pri_key, strlen(pri_key), 0, buff, &buffLen);
	if(b != 0)
	{
		printf("转换 pri_key 失败\n");
	}
	c1[0]=0x04;
	b = hexCharStr2unsignedCharStr(myC1, strlen(myC1), 0, &c1[1], &c1Len);
	if(b != 0)
	{
		printf("转换 myC1  失败\n");
	}
	// msg_len 可以用 myC2 的长度
	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	b = hexCharStr2unsignedCharStr(myC2, strlen(myC2), 0, c2, &c2Len);
	if(b != 0)
	{
		printf("转换 myC2  失败\n");
	}
	b = hexCharStr2unsignedCharStr(myC3, strlen(myC3), 0, c3, &c3Len);
	if(b != 0)
	{
		printf("转换 myC3  失败\n");
	}

	printf("... decrypt...\n");
	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		              c3,
				      c2,
				      msg_len,
				      buff,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext by using private key defined in standard failed!\n");
		return error_code;
	}
	// 对比一下看看是不是对的
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input    message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("0x%x  ", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext by using private key defined in standard succeeded!\n");

	free(plaintext);
	free(c2);
	gettimeofday(&time2, NULL);
	// 我是想看看这个时间耗时多少
	double elapsed_time = (time2.tv_sec - time1.tv_sec) * 1000.0 + (time2.tv_usec - time1.tv_usec) / 1000.0; 
	printf("the duration is : %lf \n", elapsed_time);
	vv = elapsed_time;
	return 0;
}
