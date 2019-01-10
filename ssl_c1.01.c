//gcc -o test ssl_c1.01.c -lssl -lcrypto -D_FORTIFY_SOURCE=2 -O2
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#define FAIL    -1
uint32_t iter=0;
void printStr(unsigned char *cksum_in_hex,uint16_t len);
void printK(unsigned char *cksum_in_hex);
bool testDiff(uint8_t difficult,uint8_t *tmp);
void bin2hex(uint8_t buf, uint8_t *twoBytes);
bool run=true;  // to use multi threads 
unsigned char full[1024]; // array to store string to calculate sha1sum 
// it is declared out of shah function to improve performance
struct HASH
{
	size_t strRandLen;
	unsigned char strRand[129];
	unsigned char key[129];
	uint8_t dif;
	uint8_t nThread;
	unsigned char digest[SHA_DIGEST_LENGTH];
}Hash;

/************************************************************************************
 * Generate a random string size len between start and end and store it on strRes   *
 ***********************************************************************************/	
void randStr(size_t len, size_t start, size_t end, unsigned char *strRes)
{
	static size_t seedRenew;
	size_t intervalLength = end - start + 1; // +1 for inclusive range
	iter++;
	for (uint8_t i = 0; i < len; i++) 
	{
		strRes[i]  = (uint8_t) (rand() % intervalLength) + start;
	}
	strRes[len] = '\0'; 
}

/**********************************************************************************
 *         Test if the number of zeros is equal to dificulty level 
 **********************************************************************************/
bool testDiff(uint8_t difficulty,uint8_t *tmp)
{
	uint8_t count=0;
	uint8_t i=0;
	uint8_t temp;
	for(i=0; i< 20; i++)
	{	
		for(int n=0; n < (difficulty/2) ;n++) 
						if((uint8_t)tmp[n]!=0)
										return false;

		if(((difficulty%2)!=0)&&(((uint8_t)tmp[difficulty/2] & 0xf0)!=0)) // odd ? and first nib of last byte is zero ?
		{
			return false;
		}
		else if(((uint8_t)tmp[difficulty/2] & 0xf0)==0 ) 
			{
				count++;
			}

		if((uint8_t)tmp[i] ==0)
		{
			count +=2;
		}
		if(count>=difficulty)
		{
			printf("--------------------------------------------------------\n");
			printf("Count = %d,  difficulty = %d %s\n",count,difficulty,tmp);
			printStr(tmp,20);
			return true;
		}
	}
	return false;
}

/*****************************************************************************
 * just print string as HEX format
 *****************************************************************************/	
void printK(unsigned char *cksum_in_hex)
{
	for(uint16_t i=0 ; i<SHA_DIGEST_LENGTH;i++)
	{
		printf("%02x",cksum_in_hex[i]);
		//printf("%c",cksum_in_hex[i]);
	}
	printf("\n");
}
void printStr(unsigned char *cksum_in_hex,uint16_t len )
{
	for(uint16_t i=0 ; i<len;i++)
	{
		printf("%02x",cksum_in_hex[i]);
	}
	printf("\n");
}

/*****************************************************************************
  Calculate sha1sum 
 *****************************************************************************/
void *shah(struct HASH *sh)
{
	run = true;
	size_t i=0;
	int n=0;
	unsigned long tnow=time(0);

	for(n=0;n<strlen(sh->key);n++) {
					full[n]=sh->key[n]; //copy key to full , it is a patial string to test
	}

	while(true)
	{
		//srand(time(0)+i); // divesify seed
		randStr(sh->strRandLen,0x21,0x7e, sh->strRand); // create a random string size, begin, end, return

		// using 0x21 to 0xFE is faster...
		for(n=64;n<(64+sh->strRandLen);n++)
		{
			full[n]=sh->strRand[n-64]; // copy sufix to full
			full[n+1]='\0';
		}
		SHA1((unsigned char*)&full, strlen(full), (unsigned char*)&sh->digest); // calculate sha1sum from full (server data + randStr)

		if(i%1000000==0) // print something while wait
		{
			printf( "Total time until now: %lu seconds \r",time(0)-tnow);
			//	printK(sh->digest);
		}
		if((time(0)-tnow) > 7200 )exit(1);  //check for server timeout

		bool f= testDiff(sh->dif,(uint8_t*)sh->digest); // check if sha1sum has enought number fo zeros 

		if(f)
		{
			unsigned long totalTime=time(0)-tnow;
			printf("******* Key found  ****** \n with iteractions:: %lu \n Total Time: %lu secounds \n String : %s\n SHA1SUM: ",i,totalTime,full);
			printK(sh->digest);
			printf("Current Thread: %d\n" ,sh->nThread);
			run=false;
			return sh->strRand;
		}
		i++;
		if(!run) {
			break;
		}
	}
}
/*************************************************************************
 *Added the LoadCertificates how in the server-side makes.    
 *************************************************************************/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

int OpenConnection(const char *hostname, int port)
{   
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	if ((host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}

SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = TLSv1_2_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */

	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	return ctx;
}
void ShowCerts(SSL* ssl)
{   
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */

	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("No certificates.\n");
}

/***********************************************************************************
 *   tokenizer buffer
 ***********************************************************************************/
void split(char *buffer,char token, char args[4][1024])
{
	uint16_t i=0;
	uint16_t id=0;
	uint16_t idArgs=0;
	while(buffer[i]!='\n')
	{
		if(buffer[i]==token)
		{
			args[idArgs][id]='\0';
			id=0;
			idArgs++;
			i++;
		}else
		{
			args[idArgs][id]=buffer[i];
			i++;
			id++;
		}	
		if(buffer[i]=='\n' || buffer[i]==' ') 
		{
			args[idArgs][id]='\0';
		}
	}
}

/*******************************************************************
 *	Convert binary to ascii 
 ********************************************************************/
void toHex(unsigned char* key, unsigned char *res)
{
	unsigned char test[1024];
	uint8_t twoBytes[3];
	uint8_t idx=0;
	for(uint16_t i=0 ; i<SHA_DIGEST_LENGTH;i++)
	{
		bin2hex(key[i],twoBytes);
		res[idx]=twoBytes[0];
		res[idx+1]=twoBytes[1]; 
		idx+=2;			
	}
	res[idx]='\0';
}

void bin2hex(uint8_t buf, uint8_t *twoBytes)
{
	uint8_t lsb,usb;
	lsb=buf & 0x0f;
	usb=(buf & 0xf0) >> 4;
	//      printf("befor - > lsb %02x, usb %02x, buf %02x\n",lsb,usb,buf);
	if(lsb >= 0 && lsb < 10)lsb+= 0x30;else if(lsb >=10 && lsb < 16)lsb +=0x57; //else lsb= 0x30;
	if(usb >= 0 && usb < 10)usb+= 0x30;else if(usb >=10 && usb < 16)usb +=0x57; //else usb= 0x30;
	//      printf("after - > lsb %02x, usb %02x, buf %02x\n",lsb,usb,buf);
	twoBytes[0]=usb;
	twoBytes[1]=lsb;
}

/************************************************************************
*                   Main function
* To do ....
* optimize the code:
* Create a thread to generate random string
* create multiple threads to use the strings, inside them modify the string 
* adding a number to a group of baytes, and check if these bytes 
* do not contain \ n, \ r, ...
 *************************************************************************/

int main(int argc,char *argv[])
{
	//	pthread_t thread1, thread2, thread3;
	srand(time(0));
	char portnum[]="65535";
	if(argc > 1)
	{
		strcpy(portnum,argv[1]);	
	}
	printf("Port Number: %s\n",portnum);
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	int bytes;
	char hostname[]="18.202.148.130";
	char CertFile[] = "/home/vitor/src/teste/exasolDir/openssl/cacert.pem";
	char KeyFile[] = "/home/vitor/src/teste/exasolDir/openssl/cakey.pem";
	char Args[4][1024]={{0}};
	char Token=' ';
	//unsigned char key1[]="VxLjPtPgTbqqGDKQiStFYDBltPlwbmrtsYmzsVwrjfXWYkhMhELeafMyFHHuMXtD"; // just for test
	uint8_t Len=32; // sizeof random string 
	Hash.strRandLen = Len;
	SSL_library_init();
	ctx = InitCTX();
	LoadCertificates(ctx, CertFile, KeyFile);
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);      /* create new SSL connection state */
	SSL_set_fd(ssl, server);    /* attach the socket descriptor */
	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
		ERR_print_errors_fp(stderr);
	else   // do all
	{   
		char *msg = "EHLO\n";
		char *helo="HELO";
		//    	char *end="END";
		//    	char *name="NAME";
		char *myName=" Vitor Amarante Goulart de Christo\n";
		//    	char *mailRead="MAIL1";   	
		char *mayEmail=" vitor.christo@gmail.com\n";
		//    	char *mailNumb="MAILNUM";
		char *numbEmail=" 1\n";
		char *nameSkaype="SKYPE";
		char *mySkype=" live:vitor.christo\n";
		char *birthDate="BIRTHDATE";
		char *myBirthDate=" 06.06.1961\n";
		char *country="COUNTRY";
		char *myCountry=" Portugal\n";
		char *addrNumb="ADDRNUM";
		char *addnum=" 2\n";
		char *addL1="ADDRLINE1";
		char *addL2="ADDRLINE2";
		char *waddL1=" Rua Professor Mira Fernndes L 7\n";
		char *waddL2=" 6 dto 1900-385 Lisboa\n";
		unsigned char ustr[1024];
		char aut[1024];
		char data[128];
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);        /* get any certs */
		char sufix_hex[Len+2];
		/***************************************************************************
		 *                                 Loop 
		 ***************************************************************************/
		while(true)
		{
			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
			buf[bytes] = 0; // \0 end of string
			if(bytes > 0)
			{
				printf("Received:%s", buf);
				split(buf,Token,Args);
				if(strcmp(helo,Args[0])==0)
				{
					SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
					printf("HELO received, send msg: %s\n",msg);
				}
				else
					if(strcmp(Args[0],"POW")==0)
					{
						printf("64 bytes from server : %s\n",Args[1]);
						printf("difficulte level :%s\n",Args[2]);

						strcpy(aut,Args[1]);
						strcpy(Hash.key,Args[1]);
						//		strcpy(Hash.key,key1);
						Hash.dif = atoi(Args[2]);
						//		Hash.dif = 6;
						printf("Starting decrypt... \n");
						shah(&Hash);   // *** calculate sha1sum
						sprintf(sufix_hex,"%s\n",Hash.strRand);
						SSL_write(ssl, sufix_hex, strlen(sufix_hex));
					}else
						/******************************************************************
						 *	sends sufix to server and registration data 
						 ****************************************************************/
						if(strcmp("END",Args[0])==0)
						{
							SSL_write(ssl, "OK\n", 3);
							printf("Process completed successfully\n");
							exit(1);
						}else
							if(strcmp("ERROR",Args[0])==0)
							{
								printf("Error: %s\n",Args[1]);
								exit(1);
							}else
								if(strcmp("NAME",Args[0])==0)
								{
									sprintf(ustr,"%s%s",aut,Args[1]);
									SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
									toHex(ustr,data);
									sprintf(data,"%s%s",data,myName);
									SSL_write(ssl, data, strlen(data));
									printf("Sent : %s", data);
								}
								else
									if(strcmp("MAILNUM",Args[0])==0)
									{	
										sprintf(ustr,"%s%s",aut,Args[1]);
										SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
										toHex(ustr,data);
										sprintf(data,"%s%s",data,numbEmail);
										SSL_write(ssl, data, strlen(data));
										printf("Sent : %s", data);
									}
									else
										if(strcmp("MAIL1",Args[0])==0)
										{
											sprintf(ustr,"%s%s",aut,Args[1]);
											SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
											toHex(ustr,data);
											sprintf(data,"%s%s",data,mayEmail);
											SSL_write(ssl, data, strlen(data));
											printf("Sent : %s", data);
										}
										else
											if(strcmp(nameSkaype,Args[0])==0)
											{
												sprintf(ustr,"%s%s",aut,Args[1]);
												SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
												toHex(ustr,data);
												sprintf(data,"%s%s",data,mySkype);
												SSL_write(ssl, data, strlen(data));
												printf("Sent : %s", data);
											}
											else
												if(strcmp(birthDate,Args[0])==0)
												{
													sprintf(ustr,"%s%s",aut,Args[1]);
													SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
													toHex(ustr,data);
													sprintf(data,"%s%s",data,myBirthDate);
													SSL_write(ssl, data, strlen(data));
													printf("Sent : %s", data);
												}	
												else
													if(strcmp(country,Args[0])==0)
													{
														sprintf(ustr,"%s%s",aut,Args[1]);
														SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
														toHex(ustr,data);
														sprintf(data,"%s%s",data,myCountry);
														SSL_write(ssl, data, strlen(data));
														printf("Sent : %s", data);
													}
													else
														if(strcmp(addrNumb,Args[0])==0)
														{
															sprintf(ustr,"%s%s",aut,Args[1]);
															SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
															toHex(ustr,data);
															sprintf(data,"%s%s",data,addnum);
															SSL_write(ssl, data , strlen(data));
															printf("Sent : %s", data);
														}
														else
															if(strcmp(addL1,Args[0])==0)
															{
																sprintf(ustr,"%s%s",aut,Args[1]);
																SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
																toHex(ustr,data);
																sprintf(data,"%s%s",data,waddL1);
																SSL_write(ssl, data, strlen(data));
																printf("Sent : %s", data);
															}
															else
																if(strcmp(addL2,Args[0])==0)
																{
																	sprintf(ustr,"%s%s",aut,Args[1]);
																	SHA1((unsigned char*)&ustr, strlen(ustr), (unsigned char*)&ustr);
																	toHex(ustr,data);
																	sprintf(data,"%s%s",data,waddL2);
																	SSL_write(ssl,data , strlen(data));
																	printf("Sent : %s", data);
																}
			}
		}
		//		printf("this is the sufix : %s\n",Hash.strRand);
		SSL_free(ssl); /* release connection state */
	}
	close(server);         /* close socket */
	SSL_CTX_free(ctx);        /* release context */
	return 0;
}
