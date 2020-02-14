#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h" 

// input : ./prog filename

long key; // symmetric key
long buf, n, infile, outfile;

MD5_CTX mdContext;  // needed to compute MD5

void encrypt(char *name)
{ 
  struct stat st;
  long size;
  int i,j;
  long *temp, result;   
  long rollingkey;

  // preliminaries, get files ready and sized
  infile = open (name, O_RDONLY);
  if (infile<0) { printf("input file %s open error\n", name); exit(0); }
  
  outfile = open ("output", O_RDWR|O_CREAT|O_TRUNC, 0700);
  if (outfile<0) { printf("Cannot access file: output\n"); exit(0); }
  
  stat(name, &st); size = st.st_size;
  if (size <8) {printf("input file too small\n"); exit(0);}; 
  write(outfile,&size,8); // write input file size to output
  
  // do the encryption, buf contains plaintext, and rollingkey contains key
  buf = 0;
  rollingkey = key;  
  while ((n = read(infile, &buf, 8)) > 0 ) {
    buf = buf ^ rollingkey; //XOR with key, and put ciphertext in buf
    MD5Init(&mdContext);  // compute MD5 of rollingkey
    MD5Update(&mdContext, &rollingkey, 8);
    MD5Final(&mdContext);
    temp = (long *) &mdContext.digest[8]; 
    result = *temp; // result is 64 bits of MD5 of buf
      
    rollingkey = rollingkey ^ result; // new key
    write(outfile, &buf, 8);  // write ciphertext
    buf = 0; // rinse and repeat
  }
  close(infile); close(outfile);
}

long mykeygen() // generate a key, from system entropy
{ 
  int fd = open("/dev/urandom", O_RDONLY);
  read(fd, &buf, 8);
  return(buf);
}

void main(int argc, char *argv[])
{
 if (argc!= 2) {printf("Usage: %s <filename>\n", argv[0]); exit(0);};
 
 key = mykeygen(); // generate encryption key

 encrypt(argv[1]); // encrypt input file and place in "output"

 printf ("key: %lx  <needed for decryption>\n", key);
}
