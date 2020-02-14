//answer:
//pdf: ccaf4b98
//png: 5ff10840
//txt: 2da982da

//readme
//The program will print the answer keys I got at the beginning
//Then run the brute-force algorithm to get the answer which will take very long time
//Please press ctrl + c if you want to stop the program
//run
//1. please name the encrypted PDF file as 'pdf-encr32', the encrypted PNG file as 'image-encr32', the encrypted TXT file as 'text-encr32'
//2. rum "gcc bruteforxe.c"

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"

// input : ./prog key

unsigned int key;
int buf, n, infile, outfile;
char hex[8];
long txt_hdr;


MD5_CTX mdContext; 

/*
lastbytes(int outfile, int size, int buf) // magic code for extracting last bytes of encryption without the padding
{ 
  int i = 0;
  char *last;
  last = (char*) &buf;
  for (i=0;i<size;i++) {write(outfile, &last[i], 1);} 
};*/

// PDF
decrypt_pdf(int key)
{
  struct stat st;
  int size,fsize;
  int *temp, result;   
  int rollingkey;    
  rollingkey = key;   
 
  infile = open ("pdf-encr32", O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }
  
  buf = 0;
  read(infile,&buf,4);
  size=buf; // get plaintext size

  // ciphertext has xtra 4 bytes (size) and padding 

  stat("pdf-encr32", &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

  // outfile = open ("output-pdf", O_RDWR|O_CREAT|O_TRUNC, 0700);
  // if (outfile<0) { printf("output open error\n"); exit(0); }
  
  size = 4;
  while ((n = read(infile, &buf, 4))> 0 & size > 0) {
      buf = buf ^ rollingkey; // doing the reverse of encrypt
      MD5Init(&mdContext);
      MD5Update(&mdContext, &rollingkey, 4);
      MD5Final(&mdContext);
      temp = (int *) &mdContext.digest[12]; 
      result = *temp; // result is 32 bits of MD5 of key
      rollingkey = rollingkey ^ result; // new key

      // if (size >= 4) write(outfile, &buf, 4);  
      // else lastbytes(outfile, size, buf);

      hex[0] = buf;
      hex[1] = buf>>8;
      hex[2] = buf>>16;
      hex[3] = buf>>24;

      buf = 0;  // repeat, keep track of output size in size.
      size = size - 4;
  };
  close(outfile);
};

// PNG
decrypt_image(int key)
{
  struct stat st;
  int size,fsize;
  int *temp, result;   
  int rollingkey;    
  rollingkey = key;   
 
  infile = open ("image-encr32", O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }
  
  buf = 0;
  read(infile,&buf,4);
  size=buf; // get plaintext size

  // ciphertext has xtra 4 bytes (size) and padding 

  stat("image-encr32", &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

  // outfile = open ("output-image", O_RDWR|O_CREAT|O_TRUNC, 0700);
  // if (outfile<0) { printf("output open error\n"); exit(0); }
  
  size = 4;
  while ((n = read(infile, &buf, 4))> 0 & size > 0) {
      buf = buf ^ rollingkey; // doing the reverse of encrypt
      MD5Init(&mdContext);
      MD5Update(&mdContext, &rollingkey, 4);
      MD5Final(&mdContext);
      temp = (int *) &mdContext.digest[12]; 
      result = *temp; // result is 32 bits of MD5 of key
      rollingkey = rollingkey ^ result; // new key

      // if (size >= 4) write(outfile, &buf, 4);  
      // else lastbytes(outfile, size, buf);

      hex[0] = buf;
      hex[1] = buf>>8;
      hex[2] = buf>>16;
      hex[3] = buf>>24;

      buf = 0;  // repeat, keep track of output size in size.
      size = size - 4;
  };
  close(outfile);
};

// TXT
decrypt_txt(int key)
{
  struct stat st;
  int size,fsize;
  int *temp, result;   
  int rollingkey;    
  rollingkey = key;   
 
  infile = open ("text-encr32", O_RDONLY);
  if (infile<0) { printf("input open error\n"); exit(0); }
  
  buf = 0;
  read(infile,&buf,4);
  size=buf; // get plaintext size

  // ciphertext has xtra 4 bytes (size) and padding 

  stat("text-encr32", &st); fsize = st.st_size; // get ciphertext size
  if ((fsize < 8)||(size>fsize)||(size<(fsize-8))) {printf("file size sanity check failed\n");}; 

  // outfile = open ("output-txt", O_RDWR|O_CREAT|O_TRUNC, 0700);
  // if (outfile<0) { printf("output open error\n"); exit(0); }
  
  size = 8;
  while ((n = read(infile, &buf, 4))> 0 & size > 0) {
      //printf("%d %lx\n", size, buf);
      if(size == 8){txt_hdr = buf;}

      buf = buf ^ rollingkey; // doing the reverse of encrypt
      MD5Init(&mdContext);
      MD5Update(&mdContext, &rollingkey, 4);
      MD5Final(&mdContext);
      temp = (int *) &mdContext.digest[12]; 
      result = *temp; // result is 32 bits of MD5 of key
      rollingkey = rollingkey ^ result; // new key

      // if (size >= 4) write(outfile, &buf, 4);  
      // else lastbytes(outfile, size, buf);

      hex[0+4*(2-size/4)] = buf;
      hex[1+4*(2-size/4)] = buf>>8;
      hex[2+4*(2-size/4)] = buf>>16;
      hex[3+4*(2-size/4)] = buf>>24;

      buf = 0;  // repeat, keep track of output size in size.
      size = size - 4;
  };
  close(outfile);
};

main()
{
  //print answer:
  printf("Answer:\n");
  printf("key of pdf:   ccaf4b98\n");
  printf("key of image: 5ff10840\n");
  printf("key of txt:   2da982da\n");

  //get answer
  int key = 0xFFFFFFFF;
  //int key = 0x2da982da;
  int key_pdf, key_image, key_txt;
  int Flag_pdf, Flag_image, Flag_txt;
  
  Flag_pdf = Flag_image = Flag_txt = 0;
  while(Flag_pdf*Flag_image*Flag_txt == 0 & key != 0x00000000) 
  {
	if(Flag_pdf == 0)
	{
		decrypt_pdf (key);
		if ( hex[0] =='%' &  hex[1] =='P' &  hex[2] =='D' &  hex[3] =='F') {
			key_pdf = key;
			Flag_pdf = 1;
		}
	}
	
	if(Flag_image == 0)
	{
		decrypt_image (key);
		if (hex[0] == 0xffffff89 & hex[1] =='P' &  hex[2] =='N' &  hex[3] =='G') {
			key_image = key;
			Flag_image = 1;
		}
	}
	
	if(Flag_txt == 0)
	{
		decrypt_txt (key);
		//long txt = 0x48656c6c;
		if (hex[0] <= 0x7f & hex[0] >= 0x00 \
		  & hex[1] <= 0x7f & hex[1] >= 0x00 \ 
		  & hex[2] <= 0x7f & hex[2] >= 0x00 \ 
		  & hex[3] <= 0x7f & hex[3] >= 0x00 \
		  & hex[4] <= 0x7f & hex[0] >= 0x00 \
		  & hex[5] <= 0x7f & hex[1] >= 0x00 \ 
		  & hex[6] <= 0x7f & hex[2] >= 0x00 \ 
		  & hex[7] <= 0x7f & hex[3] >= 0x00) {
			  key_txt = key;
			  Flag_txt = 1;
		}
	}
	
	//printf("try: %x\n", key);
	key--;
  } 

  printf("key for pdf file: %x\n", key_pdf);
  printf("key for image file: %x\n", key_image);
  printf("key for txt file: %x\n", key_txt);

};
