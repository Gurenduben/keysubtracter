/*
Developed by Luis Alberto
email: alberto.bsd@gmail.com
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"


const char *version = "0.2.20260922";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};

/*
	Slot of the in memory table used to find the generated publickeys,
	Only the x coordinate is needed to identify a publickey, the y parity
	completes the point.
*/
struct match_slot	{
	char x[65];		//x coordinate of the generated publickey in hexadecimal
	char privatekey[65];	//privatekey of the generated publickey in hexadecimal
	uint64_t index;		//position of that key in the generation sequence
	uint8_t used;		//1 when the slot contains a key
	uint8_t odd;		//Y oddness of the generated publickey
};

void showhelp();
void set_format(char *param);
void set_look(char *param);
void set_bit(char *param);
void set_publickey(char *param);
void set_range(char *param);
void prompt_missing_options();
void generate_straddress(struct Point *publickey,bool compress,char *dst);
void generate_strrmd160(struct Point *publickey,bool compress,char *dst);
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);
void set_privatekey(char *param);
void generate_and_match();
uint64_t hash_x(char *x);
struct match_slot *match_find(struct match_slot *table,uint64_t mask,char *x,uint8_t odd);
void match_add(struct match_slot *table,uint64_t mask,char *x,char *privatekey,uint8_t odd,uint64_t index);
void show_progress(uint64_t current,uint64_t total);
int isliveoutput();

char *str_output = "keys.txt";

/* The formatters clear 132 and 42 bytes on those buffers */
char str_publickey[132];
char str_rmd160[42];
char str_address[42];

struct Point target_publickey,base_publickey,sum_publickey,negated_publickey,dst_publickey;

int FLAG_RANGE = 0;
int FLAG_BIT = 0;
int FLAG_RANDOM = 0;
int FLAG_PUBLIC = 0;
int FLAG_FORMART = 0;
int FLAG_HIDECOMMENT = 0;
int FLAG_LOOK = 0;
int FLAG_MODE = 0;
int FLAG_N;
int FLAG_PRIVATE = 0;
int FLAG_OUTPUT = 0;
int FLAG_MATCHALL = 0;
uint64_t N = 0,M;

mpz_t min_range,max_range,diff,TWO,base_key,sum_key,dst_key,private_key_found,base_privatekey;
gmp_randstate_t state;

int main(int argc, char **argv)  {
	FILE *OUTPUT;
	int c;
	int found = 0;
	uint64_t i = 0;
	mpz_init(private_key_found);
	mpz_init(base_privatekey);
	mpz_init_set_str(EC.p, EC_constant_P, 16);
	mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);

	mpz_init(min_range);
	mpz_init(max_range);
	mpz_init(diff);
	mpz_init_set_ui(TWO,2);
	mpz_init(target_publickey.x);
	mpz_init_set_ui(target_publickey.y,0);
	while ((c = getopt(argc, argv, "hvxRab:n:o:p:r:f:l:k:")) != -1) {
		switch(c) {
			case 'x':
				FLAG_HIDECOMMENT = 1;
			break;
			case 'a':
				FLAG_MATCHALL = 1;
			break;
			case 'h':
				showhelp();
				exit(0);
			break;
			case 'b':
				set_bit((char *)optarg);
				FLAG_BIT = 1;
			break;
			case 'n':
				N = strtol((char *)optarg,NULL,10);
				if(N<= 0)	{
					fprintf(stderr,"[E] invalid bit N number %s\n",optarg);
					exit(0);
				}
				FLAG_N = 1;
			break;
			case 'o':
				str_output = (char *)optarg;
				FLAG_OUTPUT = 1;
			break;
			case 'p':
				set_publickey((char *)optarg);
				FLAG_PUBLIC = 1;
			break;
			case 'r':
				set_range((char *)optarg);
				FLAG_RANGE = 1;
			break;
			case 'R':
				FLAG_RANDOM = 1;
			break;
			case 'v':
				printf("version %s\n",version);
				exit(0);
			break;
			case 'l':
				set_look((char *)optarg);
			break;
			case 'f':
				set_format((char *)optarg);
			break;
			case 'k':
				set_privatekey((char *)optarg);
				FLAG_PRIVATE = 1;
			break;
		}
	}
	prompt_missing_options();
	if(FLAG_PRIVATE)	{
		generate_and_match();
	}
	else if((FLAG_BIT || FLAG_RANGE) && FLAG_PUBLIC && FLAG_N)	{
		if(str_output)	{
			OUTPUT = fopen(str_output,"a");
			if(OUTPUT == NULL)	{
				fprintf(stderr,"can't opent file %s\n",str_output);
				OUTPUT = stdout;
			}
		}
		else	{
			OUTPUT = stdout;
		}
		if(N % 2 == 1)	{
			N++;
		}
		M = N /2;
		mpz_sub(diff,max_range,min_range);
		mpz_init(base_publickey.x);
		mpz_init(base_publickey.y);
		mpz_init(sum_publickey.x);
		mpz_init(sum_publickey.y);
		mpz_init(negated_publickey.x);
		mpz_init(negated_publickey.y);
		mpz_init(dst_publickey.x);
		mpz_init(dst_publickey.y);
		mpz_init(base_key);
		mpz_init(sum_key);
	
		if(FLAG_RANDOM)	{
			gmp_randinit_mt(state);
			gmp_randseed_ui(state, ((int)clock()) + ((int)time(NULL)) );
			for(i = 0; i < M;i++)	{
				mpz_urandomm(base_key,state,diff);
				Scalar_Multiplication(G,&base_publickey,base_key);
				Point_Negation(&base_publickey,&negated_publickey);
				Point_Addition(&base_publickey,&target_publickey,&dst_publickey);
				
				switch(FLAG_FORMART)	{
					case 0: //Publickey
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_publickey,base_key);
						}
						
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_publickey,base_key);
						}
					break;
					case 1: //rmd160
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_rmd160,base_key);
						}
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_rmd160,base_key);
						}
					break;
					case 2:	//address
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # - %Zd\n",str_address,base_key);
						}
						Point_Addition(&negated_publickey,&target_publickey,&dst_publickey);
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # + %Zd\n",str_address,base_key);
						}
					break;
				}
			}
			
			switch(FLAG_FORMART)	{
				case 0: //Publickey
					generate_strpublickey(&target_publickey,FLAG_LOOK == 0,str_publickey);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_publickey);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_publickey);
					}
				break;
				case 1: //rmd160
					generate_strrmd160(&target_publickey,FLAG_LOOK == 0,str_rmd160);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_rmd160);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_rmd160);
					}
				break;
				case 2:	//address
					generate_straddress(&target_publickey,FLAG_LOOK == 0,str_address);
					if(FLAG_HIDECOMMENT)	{
						fprintf(OUTPUT,"%s\n",str_address);
					}
					else	{
						fprintf(OUTPUT,"%s # target\n",str_address);
					}
				break;
			}
		}
		else	{
			mpz_set(sum_key,min_range);
			for(i = 0; i < N && mpz_cmp(sum_key,max_range) <= 0;i++)	{
				Scalar_Multiplication(G,&dst_publickey,sum_key);
				switch(FLAG_FORMART)	{
					case 0: //Publickey
						generate_strpublickey(&dst_publickey,FLAG_LOOK == 0,str_publickey);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_publickey);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # %Zd\n",str_publickey,sum_key);
						}
					break;
					case 1: //rmd160
						generate_strrmd160(&dst_publickey,FLAG_LOOK == 0,str_rmd160);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_rmd160);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # %Zd\n",str_rmd160,sum_key);
						}
					break;
					case 2:	//address
						generate_straddress(&dst_publickey,FLAG_LOOK == 0,str_address);
						if(FLAG_HIDECOMMENT)	{
							fprintf(OUTPUT,"%s\n",str_address);
						}
						else	{
							gmp_fprintf(OUTPUT,"%s # %Zd\n",str_address,sum_key);
						}
					break;
				}
				if(mpz_cmp(dst_publickey.x,target_publickey.x) == 0 && mpz_cmp(dst_publickey.y,target_publickey.y) == 0)	{
					gmp_fprintf(stderr,"[+] Private key found: %Zx\n",sum_key);
					found = 1;
					break;
				}
				mpz_add_ui(sum_key,sum_key,1);
			}
			if(!found)	{
				fprintf(stderr,"[-] Private key not found in the specified range\n");
			}
		}
		
		mpz_clear(base_publickey.x);
		mpz_clear(base_publickey.y);
		mpz_clear(sum_publickey.x);
		mpz_clear(sum_publickey.y);
		mpz_clear(negated_publickey.x);
		mpz_clear(negated_publickey.y);
		mpz_clear(dst_publickey.x);
		mpz_clear(dst_publickey.y);
		mpz_clear(base_key);
		mpz_clear(sum_key);
		mpz_clear(private_key_found);
	}
	else	{
		fprintf(stderr,"Version: %s\n",version);
		fprintf(stderr,"[E] there are some missing parameter\n");
		showhelp();
	}
	return 0;
}

void showhelp()	{
	printf("\nUsage:\n-h\t\tshow this help\n");
	printf("-a\t\tWith -k do not stop on the first match, look for all of them\n");
	printf("-b bits\t\tFor some puzzles you only need a bit range\n");
	printf("-f format\tOutput format <publickey, rmd160, address>. Default: publickey\n");
	printf("-k key\t\tGenerate -n private/publickey pairs from that privatekey and\n");
	printf("\t\tsubstract them from the -p publickey until one of the generated\n");
	printf("\t\tpublickeys is reached, nothing is stored, the keys are printed to\n");
	printf("\t\tthe stdout while they are generated, with -R the offsets\n");
	printf("\t\tspace is set with -r A:B or -b bits\n");
	printf("-l look\t\tOutput <compress, uncompress>. Default: compress\n");
	printf("-n number\tNumber of publikeys to be geneted, this numbe will be even\n");
	printf("-o file\t\tOutput file, default: keys.txt\n");
	printf("-p key\t\tPublickey to be substracted compress or uncompress\n");
	printf("-r A:B\t\trange A to B\n");
	printf("-R\t\tSet the publickey substraction Random instead of secuential\n");
	printf("-x\t\tExclude comment\n");
	printf("If -p, -b/-r or -n are omitted, the program will prompt for them interactively.\n\n");
	printf("Developed by gurenduben\n\n");
}

void prompt_missing_options()	{
	char buffer[256];
	if(!FLAG_PUBLIC)	{
		printf("Enter the public key (compress or uncompress): ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			set_publickey(buffer);
			FLAG_PUBLIC = 1;
		}
	}
	if(!FLAG_BIT && !FLAG_RANGE && !FLAG_PRIVATE)	{
		printf("Enter the bit range (e.g. 32, 160): ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			buffer[strcspn(buffer,"\n")] = 0;
			set_bit(buffer);
			FLAG_BIT = 1;
		}
	}
	if(!FLAG_N)	{
		printf("Enter how many public keys to generate: ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			N = strtol(buffer,NULL,10);
			if(N <= 0)	{
				fprintf(stderr,"[E] invalid N number %s\n",buffer);
				exit(0);
			}
			FLAG_N = 1;
		}
	}
}

void set_bit(char *param)	{
	mpz_t MPZAUX;
	int bitrange = strtol(param,NULL,10);
	if(bitrange > 0 && bitrange <=256 )	{
		mpz_init(MPZAUX);
		mpz_pow_ui(MPZAUX,TWO,bitrange-1);
		mpz_set(min_range,MPZAUX);
		mpz_pow_ui(MPZAUX,TWO,bitrange);
		mpz_sub_ui(MPZAUX,MPZAUX,1);
		mpz_set(max_range,MPZAUX);
		gmp_fprintf(stderr,"[+] Min range: %Zx\n",min_range);
		gmp_fprintf(stderr,"[+] Max range: %Zx\n",max_range);
		mpz_clear(MPZAUX);
	}
	else	{
		fprintf(stderr,"[E] invalid bit param: %s\n",param);
		exit(0);
	}
}

void set_publickey(char *param)	{
	char hexvalue[65];
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memset(hexvalue,0,65);
	memcpy(dest,param,len);
	trim(dest," \t\n\r");
	len = strlen(dest);
	switch(len)	{
		case 66:
			mpz_set_str(target_publickey.x,dest+2,16);
		break;
		case 130:
			memcpy(hexvalue,dest+2,64);
			mpz_set_str(target_publickey.x,hexvalue,16);
			memcpy(hexvalue,dest+66,64);
			mpz_set_str(target_publickey.y,hexvalue,16);
		break;
	}
	if(mpz_cmp_ui(target_publickey.y,0) == 0)	{
		mpz_t mpz_aux,mpz_aux2,Ysquared;
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		mpz_init(Ysquared);
		mpz_pow_ui(mpz_aux,target_publickey.x,3);
		mpz_add_ui(mpz_aux2,mpz_aux,7);
		mpz_mod(Ysquared,mpz_aux2,EC.p);
		mpz_add_ui(mpz_aux,EC.p,1);
		mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
		mpz_powm(target_publickey.y,Ysquared,mpz_aux2,EC.p);
		mpz_sub(mpz_aux, EC.p,target_publickey.y);
		switch(dest[1])	{
			case '2':
				if(mpz_tstbit(target_publickey.y, 0) == 1)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			case '3':
				if(mpz_tstbit(target_publickey.y, 0) == 0)	{
					mpz_set(target_publickey.y,mpz_aux);
				}
			break;
			default:
				fprintf(stderr,"[E] Some invalid bit in the publickey: %s\n",dest);
				exit(0);
			break;
		}
		mpz_clear(mpz_aux);
		mpz_clear(mpz_aux2);
		mpz_clear(Ysquared);
	}
	free(dest);
}

void set_range(char *param)	{
	Tokenizer tk;
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memcpy(dest,param,len);
	dest[len] = '\0';
	stringtokenizer(dest,&tk);
	if(tk.n == 2)	{
		mpz_init_set_str(min_range,nextToken(&tk),16);
		mpz_init_set_str(max_range,nextToken(&tk),16);
	}
	else	{
		fprintf(stderr,"%i\n",tk.n);
		fprintf(stderr,"[E] Invalid range expected format A:B\n");
		exit(0);
	}
	freetokenizer(&tk);
	free(dest);
}

void set_format(char *param)	{
	int index = indexOf(param,formats,3);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknow format: %s\n",param);
	}
	else	{
		FLAG_FORMART = index;
	}
}

void set_look(char *param)	{
	int index = indexOf(param,looks,2);
	if(index == -1)	{
		fprintf(stderr,"[E] Unknow look: %s\n",param);
	}
	else	{
		FLAG_LOOK = index;
	}
}


void generate_strpublickey(struct Point *publickey,bool compress,char *dst)	{
	memset(dst,0,132);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (dst,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(dst,67,"03%0.64Zx",publickey->x);
		}
	}
	else	{
		gmp_snprintf(dst,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
	}
}

void generate_strrmd160(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	unsigned char bin_publickey[65];
	char bin_sha256[32];
	char bin_rmd160[20];
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_rmd160);
	tohex_dst(bin_rmd160,20,dst);
}

void generate_straddress(struct Point *publickey,bool compress,char *dst)	{
	char str_publickey[131];
	unsigned char bin_publickey[65];
	char bin_sha256[32];
	char bin_digest[60];
	size_t pubaddress_size = 42;
	memset(dst,0,42);
	if(compress)	{
		if(mpz_tstbit(publickey->y, 0) == 0)	{	// Even
			gmp_snprintf (str_publickey,67,"02%0.64Zx",publickey->x);
		}
		else	{
			gmp_snprintf(str_publickey,67,"03%0.64Zx",publickey->x);
		}
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 33, bin_sha256);
	}
	else	{
		gmp_snprintf(str_publickey,131,"04%0.64Zx%0.64Zx",publickey->x,publickey->y);
		hexs2bin(str_publickey,bin_publickey);
		sha256(bin_publickey, 65, bin_sha256);
	}
	RMD160Data((const unsigned char*)bin_sha256,32, bin_digest+1);
	
	/* Firts byte 0, this is for the Address begining with 1.... */
	
	bin_digest[0] = 0;
	
	/* Double sha256 checksum */	
	sha256(bin_digest, 21, bin_digest+21);
	sha256(bin_digest+21, 32, bin_digest+21);
	
	/* Get the address */
	if(!b58enc(dst,&pubaddress_size,bin_digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

/*
	Read the base privatekey used to generate the keys with the -k parameter
*/
void set_privatekey(char *param)	{
	char *dest;
	int len;
	len = strlen(param);
	dest = (char*) calloc(len+1,1);
	if(dest == NULL)	{
		fprintf(stderr,"[E] Error calloc\n");
		exit(0);
	}
	memcpy(dest,param,len);
	dest[len] = '\0';
	trim(dest," \t\n\r");
	if(dest[0] == '0' && (dest[1] == 'x' || dest[1] == 'X'))	{
		memmove(dest,dest+2,strlen(dest) - 1);
	}
	if(strlen(dest) == 0 || !isValidHex(dest))	{
		fprintf(stderr,"[E] Invalid privatekey, expected an hexadecimal value: %s\n",param);
		exit(0);
	}
	if(mpz_set_str(base_privatekey,dest,16) != 0)	{
		fprintf(stderr,"[E] Invalid privatekey: %s\n",param);
		exit(0);
	}
	free(dest);
	if(mpz_cmp_ui(base_privatekey,0) <= 0 || mpz_cmp(base_privatekey,EC.n) >= 0)	{
		fprintf(stderr,"[E] The privatekey must be greater than 0 and lower than the curve order\n");
		gmp_fprintf(stderr,"[E] Curve order: %Zx\n",EC.n);
		exit(0);
	}
}

/*
	FNV-1a of the x coordinate, the table of generated publickeys is indexed
	by that value
*/
uint64_t hash_x(char *x)	{
	uint64_t hash = 14695981039346656037ULL;
	while(*x)	{
		hash ^= (uint64_t) (unsigned char) *x++;
		hash *= 1099511628211ULL;
	}
	return hash;
}

/*
	Look for a generated publickey, the x coordinate and the y oddness identify
	an unique point, return NULL when the publickey was not generated
*/
struct match_slot *match_find(struct match_slot *table,uint64_t mask,char *x,uint8_t odd)	{
	uint64_t position = hash_x(x) & mask;
	while(table[position].used)	{
		if(table[position].odd == odd && strcmp(table[position].x,x) == 0)	{
			return &table[position];
		}
		position = (position + 1) & mask;
	}
	return NULL;
}

/*
	Add a generated publickey to the table, the table is always at least the
	double of the requested keys so it always has a free slot
*/
void match_add(struct match_slot *table,uint64_t mask,char *x,char *privatekey,uint8_t odd,uint64_t index)	{
	uint64_t position = hash_x(x) & mask;
	while(table[position].used)	{
		position = (position + 1) & mask;
	}
	memcpy(table[position].x,x,65);
	memcpy(table[position].privatekey,privatekey,65);
	table[position].odd = odd;
	table[position].index = index;
	table[position].used = 1;
}

int isliveoutput()	{
	return isatty(fileno(stderr));
}

void show_progress(uint64_t current,uint64_t total)	{
	if(isliveoutput())	{
		fprintf(stderr,"\r[+] keys generated and checked: %llu/%llu",(unsigned long long) current,(unsigned long long) total);
	}
	else	{
		fprintf(stderr,"[+] keys generated and checked: %llu/%llu\n",(unsigned long long) current,(unsigned long long) total);
	}
	fflush(stderr);
}

/*
	Generate N public/privatekey pairs from one base privatekey and substract
	every generated publickey from the publickey given by the user (-p) until
	the result of a substraction is one of the generated publickeys, that means
	until the publickey given by the user is the addition of two generated keys.
	The keys are generated sequentially (basekey, basekey+1, basekey+2, ...) or
	with a random offset when -R is used.
	The generated keys are never stored in a file, they are just printed to the
	stdout while they are generated, in memory every generated publickey is kept,
	indexed by its x coordinate together with its privatekey, to be able to find
	the matches.
*/
void generate_and_match()	{
	struct match_slot *table,*match;
	struct Point generated_publickey,negated_publickey,difference_publickey,check_publickey;
	char str_x[65],str_privatekey[65],str_publicdata[132];
	mpz_t offset,privatekey,target_privatekey,random_range;
	uint64_t i,count = 0,hits = 0,table_size = 1024,mask,progress;
	uint8_t odd;
	int duplicated;
	clock_t begin;
	if(!FLAG_PUBLIC)	{
		fprintf(stderr,"[E] The -p publickey is required to substract the generated publickeys\n");
		exit(0);
	}
	if(!FLAG_N || N == 0)	{
		fprintf(stderr,"[E] The -n number of keys to generate is required\n");
		exit(0);
	}
	mpz_init(offset);
	mpz_init(privatekey);
	mpz_init(target_privatekey);
	mpz_init(random_range);
	mpz_init(generated_publickey.x);
	mpz_init(generated_publickey.y);
	mpz_init(negated_publickey.x);
	mpz_init(negated_publickey.y);
	mpz_init(difference_publickey.x);
	mpz_init(difference_publickey.y);
	mpz_init(check_publickey.x);
	mpz_init(check_publickey.y);
	while(table_size < (N * 2))	{
		table_size <<= 1;
		if(table_size == 0)	{
			fprintf(stderr,"[E] Too many keys requested: %llu\n",(unsigned long long) N);
			exit(0);
		}
	}
	table = (struct match_slot*) calloc(table_size,sizeof(struct match_slot));
	if(table == NULL)	{
		fprintf(stderr,"[E] Error calloc, not enough memory to index %llu keys\n",(unsigned long long) N);
		exit(0);
	}
	mask = table_size - 1;

	gmp_fprintf(stderr,"[+] Base privatekey: %064Zx\n",base_privatekey);
	fprintf(stderr,"[+] Keys to generate and check: %llu\n",(unsigned long long) N);
	if(FLAG_OUTPUT)	{
		fprintf(stderr,"[+] This mode never stores the keys, the -o option is ignored\n");
	}
	if(FLAG_RANDOM)	{
		gmp_randinit_mt(state);
		gmp_randseed_ui(state,((int)clock()) + ((int)time(NULL)));
		if(FLAG_RANGE || FLAG_BIT)	{
			mpz_sub(random_range,max_range,min_range);
			if(mpz_cmp_ui(random_range,N) < 0)	{
				fprintf(stderr,"[E] The random offset range has less values than the keys requested with -n\n");
				exit(0);
			}
			gmp_fprintf(stderr,"[+] Generation: random offsets between %Zx and %Zx, a bigger space than -n avoids repeated generations\n",min_range,max_range);
		}
		else	{
			mpz_set_ui(random_range,N);
			mpz_mul_ui(random_range,random_range,4);
			gmp_fprintf(stderr,"[+] Generation: random offsets between 0 and %Zx, use -r A:B or -b bits to change that space\n",random_range);
		}
	}
	else	{
		fprintf(stderr,"[+] Generation: sequential offsets from 0 to %llu\n",(unsigned long long) (N - 1));
	}
	fprintf(stderr,"[+] Nothing is stored, the generated keys are only printed to the stdout\n");

	progress = N / (isliveoutput() ? 100 : 10);
	if(progress == 0)	{
		progress = 1;
	}
	begin = clock();
	for(i = 0;i < N;i++)	{
		if(FLAG_RANDOM)	{
			/*
				Random offsets, a key that was already generated is generated
				again until a new one appears
			*/
			do	{
				mpz_urandomm(offset,state,random_range);
				if(FLAG_RANGE || FLAG_BIT)	{
					mpz_add(offset,offset,min_range);
				}
				mpz_add(privatekey,base_privatekey,offset);
				mpz_mod(privatekey,privatekey,EC.n);
				Scalar_Multiplication(G,&generated_publickey,privatekey);
				gmp_snprintf(str_x,65,"%064Zx",generated_publickey.x);
				odd = (uint8_t) mpz_tstbit(generated_publickey.y,0);
				duplicated = (match_find(table,mask,str_x,odd) != NULL);
			}	while(duplicated);
		}
		else	{
			mpz_set_ui(offset,i);
			mpz_add(privatekey,base_privatekey,offset);
			mpz_mod(privatekey,privatekey,EC.n);
			Scalar_Multiplication(G,&generated_publickey,privatekey);
			gmp_snprintf(str_x,65,"%064Zx",generated_publickey.x);
			odd = (uint8_t) mpz_tstbit(generated_publickey.y,0);
		}
		count++;
		gmp_snprintf(str_privatekey,65,"%064Zx",privatekey);
		switch(FLAG_FORMART)	{
			case 1:	//rmd160
				generate_strrmd160(&generated_publickey,FLAG_LOOK == 0,str_publicdata);
			break;
			case 2:	//address
				generate_straddress(&generated_publickey,FLAG_LOOK == 0,str_publicdata);
			break;
			default:	//publickey
				generate_strpublickey(&generated_publickey,FLAG_LOOK == 0,str_publicdata);
			break;
		}
		if(FLAG_HIDECOMMENT)	{
			fprintf(stdout,"%s %s\n",str_privatekey,str_publicdata);
		}
		else	{
			fprintf(stdout,"%s %s # %llu\n",str_privatekey,str_publicdata,(unsigned long long) (i + 1));
		}
		/*
			The generated publickey and its privatekey are the only things that
			remain in memory, the key is indexed before the substraction so a
			key with the double of the privatekey of another one is found too
		*/
		match_add(table,mask,str_x,str_privatekey,odd,i);
		Point_Negation(&generated_publickey,&negated_publickey);
		Point_Addition(&target_publickey,&negated_publickey,&difference_publickey);
		gmp_snprintf(str_x,65,"%064Zx",difference_publickey.x);
		match = match_find(table,mask,str_x,(uint8_t) mpz_tstbit(difference_publickey.y,0));
		if(match != NULL)	{
			hits++;
			gmp_fprintf(stderr,"[+] Match: target publickey minus generated key #%llu is the generated key #%llu\n",(unsigned long long) (i + 1),(unsigned long long) (match->index + 1));
			fprintf(stderr,"[+]   generated privatekey #%llu: %s\n",(unsigned long long) (match->index + 1),match->privatekey);
			fprintf(stderr,"[+]   generated privatekey #%llu: %s\n",(unsigned long long) (i + 1),str_privatekey);
			mpz_set_str(target_privatekey,match->privatekey,16);
			mpz_add(target_privatekey,target_privatekey,privatekey);
			mpz_mod(target_privatekey,target_privatekey,EC.n);
			Scalar_Multiplication(G,&check_publickey,target_privatekey);
			if(mpz_cmp(check_publickey.x,target_publickey.x) == 0 && mpz_cmp(check_publickey.y,target_publickey.y) == 0)	{
				gmp_fprintf(stderr,"[+] Privatekey of the target publickey: %064Zx verified\n",target_privatekey);
			}
			else	{
				fprintf(stderr,"[E] The privatekey of the target publickey can not be verified\n");
			}
			if(!FLAG_MATCHALL)	{
				break;
			}
		}
		if((count % progress) == 0)	{
			show_progress(count,N);
		}
	}
	fprintf(stderr,"%s[+] %llu keys generated and checked in %.2f seconds\n",isliveoutput() ? "\r" : "",(unsigned long long) count,(double) (clock() - begin) / CLOCKS_PER_SEC);
	if(hits == 0)	{
		fprintf(stderr,"[-] No match: the target publickey is not the addition of two of the generated publickeys\n");
	}
	free(table);
	mpz_clear(offset);
	mpz_clear(privatekey);
	mpz_clear(target_privatekey);
	mpz_clear(random_range);
	mpz_clear(generated_publickey.x);
	mpz_clear(generated_publickey.y);
	mpz_clear(negated_publickey.x);
	mpz_clear(negated_publickey.y);
	mpz_clear(difference_publickey.x);
	mpz_clear(difference_publickey.y);
	mpz_clear(check_publickey.x);
	mpz_clear(check_publickey.y);
}
