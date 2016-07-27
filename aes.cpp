/*
 * g++ -std=c++11 aes.cpp -lssl -lcrypto
 */


#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <string>
#include <iostream>
#include <vector>

#include <openssl/aes.h>

#define CONST_UCHAR (const unsigned char*)
#define UCHAR (unsigned char*)

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c){
    return ( isalnum(c) || ( c=='+' ) || ( c=='/') );
}


std::vector<unsigned char> from_hex_string( const std::string& hex ){
    std::vector<unsigned char> hex_bytes;
    for( unsigned int i=0; i < hex.length(); i+= 2 ){
        std::string one_byte_string = hex.substr( i, 2 );
        unsigned char byte = ( unsigned char ) 
            strtol( one_byte_string.c_str(), NULL, 16 );
        hex_bytes.push_back(byte);

    }
    return hex_bytes;
}

std::string to_hex_string( const std::vector<unsigned char>& vec ){
    std::string hex_string("");

    for( unsigned int i=0; i < vec.size(); ++i ){
        unsigned char byte = vec[i];
        char tmp[4];
        sprintf( tmp, "%02x", byte );
        hex_string += tmp;
    }
    return hex_string;
}

std::vector<unsigned char> from_base64_string( const std::string& base64 ){
    int in_len = base64.size();
	const unsigned char *encoded_string = CONST_UCHAR base64.c_str();
	int i = 0;
  	int j = 0;
  	int in_ = 0;
  	unsigned char char_array_4[4], char_array_3[3];
  	//std::string ret;
    std::vector<unsigned char> ret;

  	while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
  	  char_array_4[i++] = encoded_string[in_]; in_++;
  	  if (i ==4) {
  	    for (i = 0; i <4; i++)
  	      char_array_4[i] = base64_chars.find(char_array_4[i]);

  	    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
  	    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
  	    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

  	    for (i = 0; (i < 3); i++)
  	      //ret += char_array_3[i];
          ret.push_back(char_array_3[i]);
  	    i = 0;
  	  }
  	}

  	if (i) {
  	  for (j = i; j <4; j++)
  	    char_array_4[j] = 0;

  	  for (j = 0; j <4; j++)
  	    char_array_4[j] = base64_chars.find(char_array_4[j]);

  	  char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
  	  char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
  	  char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

  	  //for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  	  for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  	}
  	return ret;
}

std::vector<unsigned char> from_string_string( const std::string& string ){
    std::vector<unsigned char> ret( string.size() );
    memcpy( ret.data(), string.c_str(), string.size() );
    return ret;
}

std::string to_string_string( const std::vector<unsigned char>& vec ){
    std::string ret;
    char tmp[vec.size()+1];
    memcpy( tmp, vec.data(), vec.size() );
    tmp[vec.size()] = '\0';
    ret = tmp;
    return ret;
}



std::string to_base64_string( const std::vector<unsigned char>& vec ){
	unsigned int in_len = vec.size();
	const unsigned char * bytes_to_encode = UCHAR vec.data();
    std::string ret;
  	int i = 0;
  	int j = 0;
  	unsigned char char_array_3[3];
  	unsigned char char_array_4[4];

  	while (in_len--) {
  	  char_array_3[i++] = *(bytes_to_encode++);
  	  if (i == 3) {
  	    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
  	    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
  	    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
  	    char_array_4[3] = char_array_3[2] & 0x3f;

  	    for(i = 0; (i <4) ; i++)
  	      ret += base64_chars[char_array_4[i]];
  	    i = 0;
  	  }
  	}

  	if (i)
  	{
  	  for(j = i; j < 3; j++)
  	    char_array_3[j] = '\0';

  	  char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
  	  char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
  	  char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
  	  char_array_4[3] = char_array_3[2] & 0x3f;

  	  for (j = 0; (j < i + 1); j++)
  	    ret += base64_chars[char_array_4[j]];

  	  while((i++ < 3))
  	    ret += '=';

  	}

  	return ret;
}




int main( int argc, char *argv[] ){



    std::cout<< "=============base64 Test==================\n";

    std::string test1 = "I'm an english word.";

    std::cout<< "test1\t\t:" << test1 << "\n";
    
    std::cout<< "test1_base64\t\t:" << to_base64_string( from_string_string( test1 ) ) << "\n";

    std::string test2 = "我是中文！！";

    std::cout<< "test2\t\t:" << test2 << "\n";
    std::cout<< "test2_base64\t\t:" << to_base64_string( from_string_string( test2 ) ) << "\n";

    std::cout<< "=============base64 Test==================\n";


#if 1
    std::string plan="0001000101a198afda78173486153566";
    std::string key ="00012001710198aeda79171460153594";
    std::string encrypt;
    std::string decrypt;


    std::vector<unsigned char> encrypt_vec(16);
    std::vector<unsigned char> decrypt_vec(16);

    auto key_vec   = from_hex_string( key );
    auto plan_vec  = from_hex_string( plan );

    std::cout << "==========\n";
    for( unsigned int i=0;i< plan_vec.size(); ++i )
        printf( "%02x", plan_vec[i] );
    std::cout << "\n==========\n";

    AES_KEY aes_enc_ctx;
    AES_set_encrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    AES_encrypt( CONST_UCHAR plan_vec.data(), UCHAR encrypt_vec.data(), &aes_enc_ctx );

    AES_set_decrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    AES_decrypt( CONST_UCHAR encrypt_vec.data(), UCHAR decrypt_vec.data(), &aes_enc_ctx );

    encrypt = to_hex_string( encrypt_vec );
    decrypt = to_hex_string( decrypt_vec );


    std::cout << "key\t\t:"  <<  key     << "\n";

    std::cout << "plan\t\t:" <<  plan    << "\n";
    std::cout << "cipher\t\t:"<< to_hex_string( encrypt_vec ) << "\n";
    std::cout << "decrypt\t\t:"<<to_hex_string( decrypt_vec )  << "\n";


#else

    std::string plan="0001000101a198af";
    std::string key ="00012001710198af";

    std::vector<unsigned char> encrypt_vec(16);
    std::vector<unsigned char> decrypt_vec(16);

    auto key_vec   = from_string_string( key );
    auto plan_vec  = from_string_string( plan );

    AES_KEY aes_enc_ctx;
    AES_set_encrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    AES_encrypt( CONST_UCHAR plan_vec.data(), UCHAR encrypt_vec.data(), &aes_enc_ctx );

    AES_set_decrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    AES_decrypt( CONST_UCHAR encrypt_vec.data(), UCHAR decrypt_vec.data(), &aes_enc_ctx );


    std::cout << "key\t\t:"  <<  key     << "\n";

    std::cout << "plan\t\t:" <<  plan    << "\n";
    std::cout << "hex_plan\t:" << to_hex_string( plan_vec ) << "\n";
    std::cout << "base64_plan\t:" << to_base64_string( plan_vec ) << "\n";

    std::cout << "hex_cipher\t:"<< to_hex_string( encrypt_vec ) << "\n";
    std::cout << "base64_cipher\t:" << to_base64_string( encrypt_vec ) << "\n";

    std::cout << "decrypt\t\t:"<< to_string_string( decrypt_vec ) << "\n";

#endif


    //auto i_vec = from_hex_string("000102030405060708090A0B0C0D0E0F");

    //AES_set_encrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    //AES_cbc_encrypt( CONST_UCHAR plan_vec.data(), UCHAR encrypt_vec.data(), 16,
    //                 &aes_enc_ctx, UCHAR i_vec.data(), AES_ENCRYPT );


    //AES_set_decrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    //AES_cbc_encrypt( CONST_UCHAR encrypt_vec.data(), UCHAR decrypt_vec.data(), 16,
    //                 &aes_enc_ctx, UCHAR i_vec.data(), AES_DECRYPT );



    //encrypt = to_hex_string( encrypt_vec );
    //decrypt = to_hex_string( decrypt_vec );


    //std::cout << "key\t:"  <<  key     << "\n";
    //std::cout << "ivec\t:"  <<  to_hex_string(i_vec) << "\n";
    //std::cout << "plan\t:" <<  plan    << "\n";
    //std::cout << "cipher\t:"<< encrypt << "\n";
    //std::cout << "decrypt\t:"<<decrypt << "\n";


    return 0;

}
