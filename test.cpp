#include "md5.h"
#include <iostream>

#include <string>

using namespace std;


std::string FileDigest(const string &file) {

    FILE * in=fopen(file.c_str(),"rb");
    if (in==NULL)
        return "ERROR";
    fseek( in, 0, SEEK_SET );
    security::md5 md5;
    unsigned long length;
	char buffer[1024];
    while ( !feof(in) ) {
        length = fread( buffer, sizeof(char), 1024, in );
        if (length > 0)
            md5.update(buffer, length);
    }
    fclose( in );
	return md5.to_string();
}

int main( int argc, char *argv[] ) {

    cout <<"FileDigest="<< FileDigest(argv[1]) << endl;
    
    security::md5 md5("aaaa");
    cout << "md5(\"aaaa\")=>"<< md5.to_string() << endl;

	return 0;
}
