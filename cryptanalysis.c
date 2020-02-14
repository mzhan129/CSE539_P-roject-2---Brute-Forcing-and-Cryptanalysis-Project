//readme
//1. Please put this cryptanalysis.c and the encrypted file under the same folder
//2. run "gcc cryptanalysis.c" 
//3. run "./a.out filename" 

/*
Weakness: 
The encrypt algorithm in encrypt.c file has weakness because it encrypt the file by applying XOR to it with a generated key every 8 byte. We can easily decrypt the key by decrypt the first 8 byte. Since the first 8 byte (except for the size of the file) refers to the type of the file. As long as we know the file  type we need the decrypt, we can apply XOR to the first 8 byte with a hex code extract from specific type header to get the key.
*/


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"

// input : ./prog key

int infile;

void main(int argc, char *argv[])
{
  long key, buf = 0;
  long rollingkey = 0xa1a0a0d474e5089;  
  struct stat st;
  long size,fsize;

  infile = open (argv[1], O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }

  buf = 0;
  read(infile,&buf,8);
  size=buf; // get plaintext size
  stat(argv[1], &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 16)||(size>fsize)||(size<(fsize-16))) {printf("file size sanity check failed\n");}; 

  read(infile, &buf, 8);
  // printf("%d", buf);
  key = buf ^ rollingkey;

  printf ("key: %lx\n", key);
}
