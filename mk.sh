#!/bin/bash
PROGRAMES="test_demo"
#INC_DIR=/root/tassl-1.1.1_lib/include
#LIB_DIR=/root/tassl-1.1.1_lib/lib
INC_DIR=/usr/local/include

LIB_DIR=/usr/lib64
if [ $1"X" == "cleanX" ]; then
printf "cleaning the programe %s.....\n" $PROGRAMES
	rm -rf ${PROGRAMES} 
else
printf "compiling the programe.....\n"
#g++ -ggdb3 -O0 -o test_demo test_demo.cpp test_sm2_sign_and_verify.cpp sm3_with_preprocess.cpp sm2_create_key_pair.cpp sm2_sign_and_verify.cpp  -I${INC_DIR}  -lssl -lcrypto  -ldl -lpthread
g++  -ggdb3 -O0 -o test_encr_decry_demo test_demo.cpp test_sm2_encrypt_and_decrypt.cpp sm2_encrypt_and_decrypt.cpp sm2_create_key_pair.cpp -I${INC_DIR}  -lssl -lcrypto  -ldl -lpthread

fi

