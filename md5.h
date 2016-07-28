#ifndef MD5_H
#define MD5_H

/* Type define */
//typedef unsigned char byte;
#include <cstdint>
#include <string>
#include <vector>

/* md5 declaration. */
namespace security{

    class md5 {
    public:
    	md5();
        md5(const void *input, unsigned long length);
    	md5(const std::string &str);
        md5(const std::vector<unsigned char> &vec );
        void update(const void *input, unsigned long length);
    	void update(const std::string &str);
        void update(const std::vector<unsigned char> &vec );
        const unsigned char* digest();
        std::string to_string();
        std::vector<unsigned char> to_vector();
    	void reset();
    private:
        void update(const unsigned char *input, unsigned long length);
    	void final();
        void transform(const unsigned char block[64]);
        void encode(const uint32_t *input, unsigned char *output, unsigned long length);
        void decode(const unsigned char *input, uint32_t *output, unsigned long length);
        std::string bytesToHexString(const unsigned char *input, unsigned long length);
    
    	/* class uncopyable */
    	md5(const md5&);
    	md5& operator=(const md5&);
    private:
        uint32_t _state[4];	/* state (ABCD) *//*寄存器ABCD*/
        uint32_t _count[2];	/* number of bits, modulo 2^64 (low-order word first) */
        unsigned char _buffer[64];	/* input buffer */
        unsigned char _digest[16];	/* message digest *//*信息摘要*/
        bool _finished;		/* calculate finished ? *//*信息摘要计算完毕？*/
    
        static const unsigned char PADDING[64];	/* padding for calculate *//*计算填充*/
    	static const char HEX[16];
        static const unsigned long BUFFER_SIZE = 1024;
    };

}

#endif/*MD5_H*/
