#include <string.h>
#include <stdio.h>
#include "sm33.h"

int main( int argc, char *argv[] )
{
	unsigned char *input = "abc";
	int ilen = 3;
	unsigned char output[32];
	int i;
	uint8_t state;

	printf("Message:\n");
	printf("%s\n",input);

	sm3_256( output, input, ilen);
	printf("Hash:\n   ");/*
	for(i=0; i<32; i++)
	{
		printf("%02x",output[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	} 
	printf("\n");*/
/*
	printf("Message:\n");
	for(i=0; i < 16; i++)
		printf("abcd");
	printf("\n");

    sm3_256_inc_init( &state );
	for(i=0; i < 16; i++)
		sm3_update( &state, "abcd", 4 );
    sm3_finish( &state, output );
    memset( &state, 0, sizeof( uint8_t ) );
	
	printf("Hash:\n   ");
	for(i=0; i<32; i++)
	{
		printf("%02x",output[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	}   
	printf("\n");
 */
    //getch();	//VS2008 
}