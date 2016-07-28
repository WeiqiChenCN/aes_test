/*
 * g++ -std=c++11 aes.cpp -lssl -lcrypto
 */

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

//#define NDEBUG
#include <cassert>

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
    std::vector<unsigned char> hex_bytes(0);
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
    std::vector<unsigned char> ret(0);

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

int pkcs5_padding( std::vector<unsigned char> &vec, unsigned int block_size ){
    if( block_size <=0 || 256 < block_size )
        return 1;
    if( 0 != ( block_size % 8 ) )
        return 1;
    block_size = block_size / 8;
    unsigned int actually_size = vec.size();
    unsigned int remainder = actually_size % block_size;
    unsigned int padding_size;
    if( 0==remainder ){
        padding_size = block_size;
    }else{
        padding_size = block_size - remainder;
    }
    vec.resize( actually_size+padding_size, padding_size );
    return 0;
}
int pkcs5_unpadding( std::vector<unsigned char> &vec ){
    unsigned int actually_size = vec.size();
    unsigned int padding_size = (unsigned int) vec[actually_size-1];
    if( padding_size == 0 )
        return 1;
    vec.resize( actually_size-padding_size );
    return 0;
}
namespace security {

    enum aes_crypt_type {
        aes_encrypt,
        aes_decrypt,
    };

    int aes_cbc_encrypt( 
            std::vector<unsigned char> const &in,
            std::vector<unsigned char> &out,
            std::vector<unsigned char> const &key,
            std::vector<unsigned char> const &iv,
            security::aes_crypt_type enc
            
    );

};


int security::aes_cbc_encrypt( 
        std::vector<unsigned char> const &_in,
        std::vector<unsigned char> &out,
        std::vector<unsigned char> const &key,
        std::vector<unsigned char> const &_iv,
        security::aes_crypt_type _enc
        
){
    //[TODO] Add log here.
    if( _in.size()==0 )
        return 1;
    if( _iv.size()!=16 )
        return 1;
    if( key.size()!=16 )
        return 1;
    int enc;
    AES_KEY aes_enc_ctx;
    std::vector<unsigned char> in = _in;
    std::vector<unsigned char> iv = _iv;
    switch( _enc ){
        case aes_encrypt:
            enc = AES_ENCRYPT;
            AES_set_encrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
            pkcs5_padding( in, 128 );
            break;
        case aes_decrypt:
            enc = AES_DECRYPT;
            AES_set_decrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
            break;
        default:
            assert( 0 );
            return 1;
    };

    unsigned int size_bytes;
    size_bytes = in.size();
    std::cout<< "size_bytes:" << size_bytes << "\n";
    assert( (size_bytes%16)==0 );
    out.resize( size_bytes );

    unsigned char *p_in  = in.data();
    unsigned char *p_out = out.data();
    unsigned char *p_iv  = iv.data();
    while( size_bytes!=0 ){
        AES_cbc_encrypt( p_in, p_out, 16, &aes_enc_ctx, p_iv, enc );
        p_in += 16;
        p_out += 16;
        size_bytes -= 16;
        std::cout<< "=====debug:in :"<< to_hex_string( in )   << "\n";
        std::cout<< "=====debug:out:"<< to_hex_string( out )  << "\n";
        std::cout<< "=====debug:iv :"<< to_hex_string( iv )   << "\n";
    }

    std::cout<< "dEBUG"<< to_hex_string( out ) <<"\n";
    if( _enc==aes_decrypt ){
        pkcs5_unpadding( out );
    }

    return 0;
}

int main( int argc, char *argv[] ){

    AES_KEY aes_enc_ctx;
    std::cout<< "=============base64 Test==================\n";
    std::string test1 = "I'm an english word.";
    std::cout<< "test1\t\t:" << test1 << "\n";
    std::cout<< "test1_base64\t\t:" << to_base64_string( from_string_string( test1 ) ) << "\n";
    std::string test2 = "我是中文！！";
    std::cout<< "test2\t\t:" << test2 << "\n";
    std::cout<< "test2_base64\t\t:" << to_base64_string( from_string_string( test2 ) ) << "\n";
    std::cout<< "=============base64 Test==================\n";
    std::string padding_test="abcdef98765432100123456789fedcba";
    std::cout<< "==========pkcs5_padding Test=================\n";
    for( unsigned int i=2; i<33; i+=2 ){
        std::vector<unsigned char> vec;
        vec = from_hex_string( padding_test.substr(0,i) );
        pkcs5_padding( vec, 128 );
        std::cout<<i<<"\t:"<< to_hex_string( vec )<<"\n";
        pkcs5_unpadding( vec );
        std::cout<<i<<"\t:"<< to_hex_string( vec )<<"\n";
    }
    std::cout<< "==========pkcs5_padding Test=================\n";


    std::string plan="0001000101a198afda78173486153566";
    std::string key ="00012001710198aeda79171460153594";
    std::string iv  ="00000000000000000000000000000000";
    std::vector<unsigned char> encrypt_vec(32), decrypt_vec(32), iv_vec, key_vec, plan_vec;
    std::cout << "===================2===================\n";

    iv_vec    = from_hex_string( iv );
    key_vec   = from_hex_string( key );
    plan_vec  = from_hex_string( plan );
 
    memset( encrypt_vec.data(), 0x10, encrypt_vec.size() );
    memset( decrypt_vec.data(), 0x10, decrypt_vec.size() );

    std::cout << "plan\t:"  <<   to_hex_string(plan_vec)   << "\n";
    std::cout << "key\t:"   <<   to_hex_string(key_vec)    << "\n";
    std::cout << "ivec\t:"  <<   to_hex_string(iv_vec)     << "\n";

    AES_set_encrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );

    AES_cbc_encrypt( CONST_UCHAR plan_vec.data(), UCHAR encrypt_vec.data(), 16,
                     &aes_enc_ctx, UCHAR iv_vec.data(), AES_ENCRYPT );

    AES_set_decrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    iv_vec = from_hex_string(iv);
    AES_cbc_encrypt( CONST_UCHAR encrypt_vec.data(), UCHAR decrypt_vec.data(), 16,
                     &aes_enc_ctx, UCHAR iv_vec.data(), AES_DECRYPT );

    std::cout << "cipher\t:"  << to_hex_string(encrypt_vec) << "\n";
    std::cout << "decrypt\t:" << to_hex_string(decrypt_vec) << "\n";

    std::cout << "===================1===================\n";
    iv_vec    = from_hex_string( iv );
#if 0
    key_vec   = from_hex_string( key );
    plan_vec  = from_hex_string( plan );
#else
    //key_vec   = from_hex_string( "129fe578f428dd8fb067f81bac6ea620" );
    key_vec   = from_base64_string( "zs8h51D6dUF6BMRuF6KtFw==" );
    plan_vec  = from_string_string( "0001000101a198af" );
#endif
    memset( encrypt_vec.data(), 0x10, encrypt_vec.size() );
    memset( decrypt_vec.data(), 0x10, decrypt_vec.size() );
    security::aes_cbc_encrypt( plan_vec,    encrypt_vec, key_vec, iv_vec, security::aes_encrypt );
    security::aes_cbc_encrypt( encrypt_vec, decrypt_vec, key_vec, iv_vec, security::aes_decrypt );
    std::cout << "plan\t:"    << to_hex_string(plan_vec)    << "\n";
    std::cout << "key\t:"     << to_hex_string(key_vec)     << "\n";
    std::cout << "iv\t:"      << to_hex_string(iv_vec)      << "\n";
    std::cout << "cipher\t:"  << to_hex_string(encrypt_vec) << "\n";
    std::cout << "decrypt\t:" << to_hex_string(decrypt_vec) << "\n";
    std::cout << "cipher_base64:" << to_base64_string( encrypt_vec ) << "\n";

#if 0
    AES_KEY aes_enc_ctx;
    std::string plan="0001000101a198afda78173486153566";
    std::string key ="00012001710198aeda79171460153594";

    std::vector<unsigned char> encrypt_vec(16);
    std::vector<unsigned char> decrypt_vec(16);

    auto key_vec   = from_hex_string( key );
    auto plan_vec  = from_hex_string( plan );

    std::cout << "==========\n";
    for( unsigned int i=0;i< plan_vec.size(); ++i )
        printf( "%02x", plan_vec[i] );
    std::cout << "\n==========\n";

    AES_set_encrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    AES_encrypt( CONST_UCHAR plan_vec.data(), UCHAR encrypt_vec.data(), &aes_enc_ctx );

    AES_set_decrypt_key( CONST_UCHAR key.data(), 128, &aes_enc_ctx );
    AES_decrypt( CONST_UCHAR encrypt_vec.data(), UCHAR decrypt_vec.data(), &aes_enc_ctx );

    std::cout << "key\t\t:"  <<  key     << "\n";

    std::cout << "plan\t\t:" <<  plan    << "\n";
    std::cout << "cipher\t\t:"<< to_hex_string( encrypt_vec ) << "\n";
    std::cout << "decrypt\t\t:"<<to_hex_string( decrypt_vec )  << "\n";
#endif

    return 0;

}
