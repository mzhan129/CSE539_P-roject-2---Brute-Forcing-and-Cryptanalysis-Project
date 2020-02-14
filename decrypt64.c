#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"

// input : ./prog key

unsigned int key;
long buf;
int n, infile, outfile;
MD5_CTX mdContext; 


void lastbytes(int outfile, long size) // magic code for extracting last bytes of encryption without the padding
{ 
  int i = 0;
  ulong *last;
  last = (ulong*) &buf;

  for (i=0;i<size;i++) 
  {
    write(outfile, &last[i], 1);
  } 
}

void decrypt(long key)
{
  struct stat st;
  long size,fsize;
  long *temp, result;   
  long rollingkey;    
  rollingkey = key;   

  infile = open ("output", O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }

  buf = 0;
  read(infile,&buf,8);
  size=buf; // get plaintext size

  // ciphertext has extra 8 bytes (size) and padding 

  stat("output", &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 16)||(size>fsize)||(size<(fsize-16))) {printf("file size sanity check failed\n");}; 

  outfile = open ("output-dec", O_RDWR|O_CREAT|O_TRUNC, 0700);
  if (outfile<0) { printf("output open error\n"); exit(0); }

  while ((n = read(infile, &buf, 8))> 0) {
    buf = buf ^ rollingkey; // doing the reverse of encrypt
    MD5Init(&mdContext);
    MD5Update(&mdContext, &rollingkey, 8);
    MD5Final(&mdContext);
    temp = (long *) &mdContext.digest[8]; 
    result = *temp; // result is 64 bits of MD5 of key
    rollingkey = rollingkey ^ result; // new key

    if (size >= 8) write(outfile, &buf, 8);  
    else lastbytes(outfile, size);

    buf = 0;  // repeat, keep track of output size in size.
    size = size - 8;
  }
}

void main(int argc, char *argv[])
{
  long key;
  sscanf(argv[1], "%lx", &key);
  decrypt(key);
}
