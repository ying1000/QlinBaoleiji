#ifndef __BASE64_H
#define __BASE64_H

#include <stdio.h>
#include <malloc.h>

void base64_encoder( const char *input, size_t len, char** out_str );

/* Read from fin file. Append write fout file */
void base64_encoder_file( FILE *fin, FILE *fout );

void base64_decoder( const char *input, size_t len, char** out_str );

#endif
