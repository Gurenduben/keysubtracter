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


const char *version = "0.3.20260926";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};

/*
	Maximum number of entries created for one search stage (baby steps of
	a BSGS search or combinations stored by a meet in the middle search)
	unless the -F parameter is used.  One stage with 4194304 entries
	already needs several seconds and hundreds of MB of RAM.
*/
#define SEARCH_ENTRY_LIMIT 4194304ULL

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

/*
	A generated private/publickey pair.  In the -k mode every generated
	key is kept in memory because the search for an addition of
	MIN_SUMMANDS or more keys needs all of them, not only the last one.
	offset is the value that was added to the base privatekey to make
	this key (the privatekey itself is already reduced modulo EC.n).
*/
struct generated_key	{
	mpz_t privatekey;
	mpz_t offset;
	struct Point publickey;
};

/* Slot of a baby step table: the point is value * G */
struct scalar_slot	{
	char x[65];
	uint64_t value;
	uint8_t used;
	uint8_t odd;
};

/*
	Slot of a meet in the middle table with the sums of some generated
	publickeys.  The indexes of those keys are not in the slot, they are
	in a separate array with table_size * keys_per_sum uint32_t values,
	so this slot stays small when millions of sums are stored.
*/
struct subset_slot	{
	char x[65];
	uint8_t used;
	uint8_t odd;
};

/* State shared by every search for additions of generated publickeys */
struct search_state	{
	struct generated_key *keys;
	uint64_t n;
	uint64_t hits;		//different matches reported
	uint64_t skipped;	//sizes that were not searched, they were too big
	char **reported;	//encoded sorted indexes of the reported matches
	uint64_t reported_count;
	uint64_t reported_capacity;
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
void set_minsummands(char *param);
void generate_and_match();
uint64_t hash_x(char *x);
struct match_slot *match_find(struct match_slot *table,uint64_t mask,char *x,uint8_t odd);
void match_add(struct match_slot *table,uint64_t mask,char *x,char *privatekey,uint8_t odd,uint64_t index);
void point_copy(struct Point *dst,struct Point *src);
int point_is_infinity(struct Point *point);
void point_negate_safe(struct Point *src,struct Point *dst);
int report_match(struct search_state *state,uint64_t *indexes,uint64_t count);
void search_state_free_reported(struct search_state *state);
int bsgs_find_scalar(struct Point *point,mpz_t low,mpz_t length,mpz_t result);
void search_sequential(struct search_state *state);
int search_bounded_offsets(struct search_state *state);
void search_meet_in_the_middle(struct search_state *state);
void show_progress(uint64_t current,uint64_t total);
int isliveoutput();
uint64_t system_ram();
void show_system_ram(uint64_t ram_needed);
void format_bytes(uint64_t bytes,char *dst,size_t dst_size);

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
int FLAG_MINSUMMANDS = 0;
int FLAG_FORCESEARCH = 0;
uint64_t N = 0,M;
uint64_t MIN_SUMMANDS = 10;

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
	while ((c = getopt(argc, argv, "hvxRaFb:n:o:p:r:f:l:k:m:")) != -1) {
		switch(c) {
			case 'x':
				FLAG_HIDECOMMENT = 1;
			break;
			case 'a':
				FLAG_MATCHALL = 1;
			break;
			case 'F':
				FLAG_FORCESEARCH = 1;
			break;
			case 'm':
				set_minsummands((char *)optarg);
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
	if(!FLAG_PRIVATE && (FLAG_MINSUMMANDS || FLAG_FORCESEARCH))	{
		fprintf(stderr,"[W] The -m and -F parameters are only used with -k, they are ignored in this mode\n");
	}
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
		/*
			In this mode every key is written while it is generated and none of them
			is kept in memory, so the RAM needed for the keys is 0 bytes
		*/
		fprintf(stderr,"[+] Estimated RAM needed: 0.00 B (0 bytes), the %llu keys are written while they are generated, none of them is kept in memory\n",(unsigned long long) N);
		show_system_ram(0);
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
	printf("-F\t\tWith -k force a search size even when its estimated number of\n");
	printf("\t\tcombinations or baby steps is over the safety limit, this can\n");
	printf("\t\tuse a lot of RAM and time\n");
	printf("-k key\t\tGenerate -n private/publickey pairs from that privatekey and\n");
	printf("\t\tcheck if the -p publickey is the addition of -m or more of the\n");
	printf("\t\tgenerated publickeys, every generated key can be used only\n");
	printf("\t\tonce in that addition, nothing is stored in a file, the keys\n");
	printf("\t\tare printed to the stdout while they are generated, with -R\n");
	printf("\t\tthe offsets space is set with -r A:B or -b bits\n");
	printf("-m number\tWith -k minimum number of distinct generated publickeys whose\n");
	printf("\t\taddition must be the -p publickey. Default: 10, with -m 2 the\n");
	printf("\t\tadditions of two generated publickeys are searched first\n");
	printf("\t\tThe estimated RAM needed for the -n keys and the system\n");
	printf("\t\tRAM are printed before the generation in every mode, a warning\n");
	printf("\t\tis shown when the estimated RAM needed does not fit\n");
	printf("-l look\t\tOutput <compress, uncompress>. Default: compress\n");
	printf("-n number\tNumber of publikeys to be geneted, this numbe will be even\n");
	printf("-o file\t\tOutput file, default: keys.txt\n");
	printf("-p key\t\tPublickey to be substracted compress or uncompress\n");
	printf("-r A:B\t\trange A to B\n");
	printf("-R\t\tSet the publickey substraction Random instead of secuential\n");
	printf("-x\t\tExclude comment\n");
	printf("If any of -p, -k, -b/-r, -n or -R are omitted, the program will prompt for them\n");
	printf("interactively: the public key, the starting private key, the bits, the number\n");
	printf("of keys to generate and whether the search is random or sequential.\n\n");
	printf("Developed by gurenduben\n\n");
}

void prompt_missing_options()	{
	char buffer[256];
	if(!FLAG_PUBLIC)	{
		printf("Enter the public key you are looking to get the private key to (compress or uncompress): ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			set_publickey(buffer);
			FLAG_PUBLIC = 1;
		}
	}
	if(!FLAG_PRIVATE)	{
		printf("Enter the private key to start from (hex): ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			buffer[strcspn(buffer,"\n")] = 0;
			set_privatekey(buffer);
			FLAG_PRIVATE = 1;
		}
	}
	if(!FLAG_BIT && !FLAG_RANGE)	{
		printf("Enter the bits (e.g. 32, 160, used as the random offset range when random search is chosen): ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			buffer[strcspn(buffer,"\n")] = 0;
			set_bit(buffer);
			FLAG_BIT = 1;
		}
	}
	if(!FLAG_N)	{
		printf("Enter the number of keys to generate: ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			buffer[strcspn(buffer,"\n")] = 0;
			N = strtol(buffer,NULL,10);
			if(N <= 0)	{
				fprintf(stderr,"[E] invalid N number %s\n",buffer);
				exit(0);
			}
			FLAG_N = 1;
		}
	}
	if(!FLAG_RANDOM)	{
		int answer;
		printf("Random or sequential search? [r/s] (default sequential): ");
		fflush(stdout);
		if(fgets(buffer,sizeof(buffer),stdin) != NULL)	{
			buffer[strcspn(buffer,"\n")] = 0;
			trim(buffer," \t\r");
			answer = buffer[0];
			if(answer == 'r' || answer == 'R')	{
				FLAG_RANDOM = 1;
			}
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
	Read the minimum number of generated publickeys that must be added
	to make the -p publickey, 10 when the -m parameter is not used
*/
void set_minsummands(char *param)	{
	char *end = NULL;
	long value;
	if(param == NULL || param[0] == '\0')	{
		fprintf(stderr,"[E] Invalid -m number, expected a positive number of publickeys\n");
		exit(0);
	}
	value = strtol(param,&end,10);
	if(end == param || *end != '\0' || value <= 0)	{
		fprintf(stderr,"[E] Invalid -m number, expected a positive number of publickeys: %s\n",param);
		exit(0);
	}
	MIN_SUMMANDS = (uint64_t) value;
	FLAG_MINSUMMANDS = 1;
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
	Print the System RAM and warn when the RAM needed does not fit in it
*/
void show_system_ram(uint64_t ram_needed)	{
	char str_bytes[64];
	uint64_t ram_total = system_ram();
	if(ram_total > 0)	{
		format_bytes(ram_total,str_bytes,sizeof(str_bytes));
		fprintf(stderr,"[+] System RAM: %s (%llu bytes)\n",str_bytes,(unsigned long long) ram_total);
		if(ram_needed > ram_total)	{
			fprintf(stderr,"[W] The estimated RAM needed is bigger than the system RAM, the allocation can fail, use a lower -n value\n");
		}
	}
	else	{
		fprintf(stderr,"[W] The system RAM can not be determined, the estimated RAM needed is %llu bytes\n",(unsigned long long) ram_needed);
	}
}

/*
	Total physical RAM of the system in bytes, 0 when it can not be determined
*/
uint64_t system_ram()	{
	long pages = sysconf(_SC_PHYS_PAGES);
	long page_size = sysconf(_SC_PAGESIZE);
	if(pages <= 0 || page_size <= 0)	{
		return 0;
	}
	return (uint64_t) pages * (uint64_t) page_size;
}

/*
	Write the given number of bytes in the dst buffer in a human readable way
*/
void format_bytes(uint64_t bytes,char *dst,size_t dst_size)	{
	static const char *units[5] = {"B","KB","MB","GB","TB"};
	double value = (double) bytes;
	int unit = 0;
	while(value >= 1024 && unit < 4)	{
		value /= 1024;
		unit++;
	}
	snprintf(dst,dst_size,"%.2f %s",value,units[unit]);
}

/*
	Copy a point, the destination must already be initialised
*/
void point_copy(struct Point *dst,struct Point *src)	{
	mpz_set(dst->x,src->x);
	mpz_set(dst->y,src->y);
}

/*
	The point at infinity is represented as (0,0) by the gmpecc code
*/
int point_is_infinity(struct Point *point)	{
	return mpz_cmp_ui(point->x,0) == 0 && mpz_cmp_ui(point->y,0) == 0;
}

/*
	Negate a point, the point at infinity is its own negation, this is
	also safe when src and dst are the same point
*/
void point_negate_safe(struct Point *src,struct Point *dst)	{
	if(point_is_infinity(src))	{
		mpz_set_ui(dst->x,0);
		mpz_set_ui(dst->y,0);
	}
	else	{
		mpz_set(dst->x,src->x);
		mpz_sub(dst->y,EC.p,src->y);
	}
}

static struct scalar_slot *scalar_find(struct scalar_slot *table,uint64_t mask,char *x,uint8_t odd)	{
	uint64_t position = hash_x(x) & mask;
	while(table[position].used)	{
		if(table[position].odd == odd && strcmp(table[position].x,x) == 0)	{
			return &table[position];
		}
		position = (position + 1) & mask;
	}
	return NULL;
}

static void scalar_add(struct scalar_slot *table,uint64_t mask,char *x,uint8_t odd,uint64_t value)	{
	uint64_t position = hash_x(x) & mask;
	while(table[position].used)	{
		position = (position + 1) & mask;
	}
	memcpy(table[position].x,x,65);
	table[position].value = value;
	table[position].odd = odd;
	table[position].used = 1;
}

/*
	Baby step giant step search of a scalar in an interval: return 1
	and write the scalar in result when a value s in
	[low, low + length] exists with s * G equal to the given point,
	return 0 when there is no such value and -1 when the search was
	not done because the baby step table would be over the limit.
	The interval length is far below the curve order in every use of
	this function, so at most one scalar can be in the interval.
*/
int bsgs_find_scalar(struct Point *point,mpz_t low,mpz_t length,mpz_t result)	{
	struct scalar_slot *table = NULL,*slot;
	struct Point current,next,factor,neg_factor,low_point,neg_low;
	mpz_t count,m,tmp,candidate;
	char str_x[65];
	uint64_t baby = 0,table_size = 1024,mask = 0,t,j;
	int found = 0;
	mpz_init(count);
	mpz_init(m);
	mpz_init(tmp);
	mpz_init(candidate);
	mpz_add_ui(count,length,1);
	mpz_sqrt(m,count);
	mpz_mul(tmp,m,m);
	if(mpz_cmp(tmp,count) < 0)	{
		mpz_add_ui(m,m,1);
	}
	if(!mpz_fits_ulong_p(m))	{
		mpz_clear(count);
		mpz_clear(m);
		mpz_clear(tmp);
		mpz_clear(candidate);
		return -1;
	}
	baby = (uint64_t) mpz_get_ui(m);
	if(baby == 0)	{
		baby = 1;
	}
	if(baby > SEARCH_ENTRY_LIMIT && !FLAG_FORCESEARCH)	{
		mpz_clear(count);
		mpz_clear(m);
		mpz_clear(tmp);
		mpz_clear(candidate);
		return -1;
	}
	if(baby > (UINT64_MAX / 2))	{
		mpz_clear(count);
		mpz_clear(m);
		mpz_clear(tmp);
		mpz_clear(candidate);
		return -1;
	}
	while(table_size < baby * 2)	{
		if(table_size > (UINT64_MAX / 2))	{
			mpz_clear(count);
			mpz_clear(m);
			mpz_clear(tmp);
			mpz_clear(candidate);
			return -1;
		}
		table_size <<= 1;
	}
	table = (struct scalar_slot*) calloc(table_size,sizeof(struct scalar_slot));
	if(table == NULL)	{
		fprintf(stderr,"[E] Error calloc, not enough memory for a baby step table of %llu entries\n",(unsigned long long) baby);
		mpz_clear(count);
		mpz_clear(m);
		mpz_clear(tmp);
		mpz_clear(candidate);
		return -1;
	}
	mask = table_size - 1;
	mpz_init_set_ui(current.x,0);
	mpz_init_set_ui(current.y,0);
	mpz_init_set_ui(next.x,0);
	mpz_init_set_ui(next.y,0);
	mpz_init_set_ui(factor.x,0);
	mpz_init_set_ui(factor.y,0);
	mpz_init_set_ui(neg_factor.x,0);
	mpz_init_set_ui(neg_factor.y,0);
	mpz_init_set_ui(low_point.x,0);
	mpz_init_set_ui(low_point.y,0);
	mpz_init_set_ui(neg_low.x,0);
	mpz_init_set_ui(neg_low.y,0);
	for(j = 0;j < baby;j++)	{
		gmp_snprintf(str_x,sizeof(str_x),"%064Zx",current.x);
		scalar_add(table,mask,str_x,(uint8_t) mpz_tstbit(current.y,0),j);
		if(j + 1 < baby)	{
			Point_Addition(&current,&G,&next);
			point_copy(&current,&next);
		}
	}
	Scalar_Multiplication(G,&factor,m);
	point_negate_safe(&factor,&neg_factor);
	Scalar_Multiplication(G,&low_point,low);
	point_negate_safe(&low_point,&neg_low);
	Point_Addition(point,&neg_low,&current);
	for(t = 0;t < baby && !found;t++)	{
		gmp_snprintf(str_x,sizeof(str_x),"%064Zx",current.x);
		slot = scalar_find(table,mask,str_x,(uint8_t) mpz_tstbit(current.y,0));
		if(slot != NULL)	{
			mpz_mul_ui(candidate,m,(unsigned long int) t);
			mpz_add_ui(candidate,candidate,(unsigned long int) slot->value);
			if(mpz_cmp(candidate,length) <= 0)	{
				mpz_add(result,low,candidate);
				found = 1;
			}
		}
		if(!found && t + 1 < baby)	{
			Point_Addition(&current,&neg_factor,&next);
			point_copy(&current,&next);
		}
	}
	free(table);
	mpz_clear(current.x);
	mpz_clear(current.y);
	mpz_clear(next.x);
	mpz_clear(next.y);
	mpz_clear(factor.x);
	mpz_clear(factor.y);
	mpz_clear(neg_factor.x);
	mpz_clear(neg_factor.y);
	mpz_clear(low_point.x);
	mpz_clear(low_point.y);
	mpz_clear(neg_low.x);
	mpz_clear(neg_low.y);
	mpz_clear(count);
	mpz_clear(m);
	mpz_clear(tmp);
	mpz_clear(candidate);
	return found;
}

void search_state_free_reported(struct search_state *state)	{
	uint64_t i;
	for(i = 0;i < state->reported_count;i++)	{
		free(state->reported[i]);
	}
	free(state->reported);
	state->reported = NULL;
	state->reported_count = 0;
	state->reported_capacity = 0;
}

/*
	Report one addition of generated publickeys that makes the target
	publickey.  The indexes must be sorted, a match that was already
	reported (the same set of keys can be found in several ways) is
	not reported again.  Return 1 when a new match was reported, the
	privatekey of the target is always verified before printing it.
*/
int report_match(struct search_state *state,uint64_t *indexes,uint64_t count)	{
	struct Point check_publickey;
	mpz_t target_privatekey;
	char *encoding,**new_reported;
	size_t encoding_size,position;
	uint64_t i;
	int verified;
	if(count == 0 || count > state->n)	{
		return 0;
	}
	encoding_size = (size_t) count * 32 + 1;
	encoding = (char*) malloc(encoding_size);
	if(encoding == NULL)	{
		fprintf(stderr,"[E] Error malloc, not enough memory to report a match\n");
		return 0;
	}
	position = 0;
	encoding[0] = '\0';
	for(i = 0;i < count;i++)	{
		position += (size_t) snprintf(encoding + position,encoding_size - position,"%llu,",(unsigned long long) indexes[i]);
	}
	for(i = 0;i < state->reported_count;i++)	{
		if(strcmp(state->reported[i],encoding) == 0)	{
			free(encoding);
			return 0;
		}
	}
	mpz_init(target_privatekey);
	mpz_init(check_publickey.x);
	mpz_init(check_publickey.y);
	for(i = 0;i < count;i++)	{
		mpz_add(target_privatekey,target_privatekey,state->keys[indexes[i]].privatekey);
	}
	mpz_mod(target_privatekey,target_privatekey,EC.n);
	Scalar_Multiplication(G,&check_publickey,target_privatekey);
	verified = (mpz_cmp(check_publickey.x,target_publickey.x) == 0 && mpz_cmp(check_publickey.y,target_publickey.y) == 0);
	if(!verified)	{
		fprintf(stderr,"[E] A candidate addition of %llu generated publickeys can not be verified\n",(unsigned long long) count);
		free(encoding);
		mpz_clear(target_privatekey);
		mpz_clear(check_publickey.x);
		mpz_clear(check_publickey.y);
		return 0;
	}
	if(state->reported_count == state->reported_capacity)	{
		state->reported_capacity = state->reported_capacity ? state->reported_capacity * 2 : 16;
		new_reported = (char**) realloc(state->reported,(size_t) state->reported_capacity * sizeof(char*));
		if(new_reported == NULL)	{
			fprintf(stderr,"[E] Error realloc, not enough memory to report a match\n");
			free(encoding);
			mpz_clear(target_privatekey);
			mpz_clear(check_publickey.x);
			mpz_clear(check_publickey.y);
			return 0;
		}
		state->reported = new_reported;
	}
	state->reported[state->reported_count++] = encoding;
	state->hits++;
	fprintf(stderr,"[+] Match: target publickey is the addition of %llu generated publickeys:",(unsigned long long) count);
	for(i = 0;i < count;i++)	{
		fprintf(stderr,"%s #%llu",i ? "," : "",(unsigned long long) (indexes[i] + 1));
	}
	fprintf(stderr,"\n");
	for(i = 0;i < count;i++)	{
		gmp_fprintf(stderr,"[+]   generated privatekey #%llu: %064Zx\n",(unsigned long long) (indexes[i] + 1),state->keys[indexes[i]].privatekey);
	}
	gmp_fprintf(stderr,"[+] Privatekey of the target publickey: %064Zx verified\n",target_privatekey);
	mpz_clear(target_privatekey);
	mpz_clear(check_publickey.x);
	mpz_clear(check_publickey.y);
	return 1;
}

/*
	Make the indexes of one set of count distinct offsets in
	[0, n - 1] with the given sum, used with the sequential keys
	where every sum between the minimum and the maximum is possible:
	start with 0,1,...,count-1 and distribute the extra sum over the
	bigger offsets without breaking the order or the n - 1 limit.
*/
static uint64_t *sequential_indexes(uint64_t n,uint64_t count,mpz_t sum,mpz_t minimum_sum)	{
	uint64_t *indexes,j;
	mpz_t extra_mpz;
	unsigned long int extra;
	indexes = (uint64_t*) calloc(count ? count : 1,sizeof(uint64_t));
	if(indexes == NULL)	{
		return NULL;
	}
	for(j = 0;j < count;j++)	{
		indexes[j] = j;
	}
	mpz_init(extra_mpz);
	mpz_sub(extra_mpz,sum,minimum_sum);
	if(!mpz_fits_ulong_p(extra_mpz))	{
		mpz_clear(extra_mpz);
		free(indexes);
		return NULL;
	}
	extra = mpz_get_ui(extra_mpz);
	mpz_clear(extra_mpz);
	for(j = count;j-- > 0 && extra > 0;)	{
		uint64_t upper = (j + 1 == count) ? n - 1 : indexes[j + 1] - 1;
		uint64_t increase = upper - indexes[j];
		if(increase > extra)	{
			increase = extra;
		}
		indexes[j] += increase;
		extra -= (unsigned long int) increase;
	}
	if(extra != 0)	{
		free(indexes);
		return NULL;
	}
	return indexes;
}

struct sum_subset_item	{
	uint64_t value;
	uint64_t index;
};

static int compare_sum_subset_items(const void *a,const void *b)	{
	const struct sum_subset_item *left = (const struct sum_subset_item*) a;
	const struct sum_subset_item *right = (const struct sum_subset_item*) b;
	if(left->value < right->value)	{
		return -1;
	}
	if(left->value > right->value)	{
		return 1;
	}
	if(left->index < right->index)	{
		return -1;
	}
	if(left->index > right->index)	{
		return 1;
	}
	return 0;
}

static int compare_generated_indexes(const void *a,const void *b)	{
	uint64_t left = *((const uint64_t*) a);
	uint64_t right = *((const uint64_t*) b);
	if(left < right)	{
		return -1;
	}
	if(left > right)	{
		return 1;
	}
	return 0;
}

struct sum_subset_search	{
	struct search_state *state;
	struct sum_subset_item *items;
	unsigned __int128 *prefix;
	uint64_t n;
	uint64_t count;
	uint64_t *chosen;
};

/*
	Enumerate sets of keys by their offset sum, the items are
	sorted by offset so the smallest and biggest sums that can
	still be made are known from the prefix sums and every branch
	that can not reach the wanted sum is cut.  This is only used
	with -a, without it one set with the wanted sum is enough.
*/
static void enumerate_sum_subsets_recursive(struct sum_subset_search *search,uint64_t start,uint64_t depth,unsigned __int128 remaining)	{
	uint64_t need,i;
	unsigned __int128 minimum_sum,maximum_sum;
	if(depth == search->count)	{
		if(remaining == 0)	{
			uint64_t *indexes = (uint64_t*) calloc(search->count ? search->count : 1,sizeof(uint64_t));
			if(indexes == NULL)	{
				fprintf(stderr,"[E] Error calloc, not enough memory to report a match\n");
				return;
			}
			for(i = 0;i < search->count;i++)	{
				indexes[i] = search->chosen[i];
			}
			qsort(indexes,(size_t) search->count,sizeof(uint64_t),compare_generated_indexes);
			report_match(search->state,indexes,search->count);
			free(indexes);
		}
		return;
	}
	need = search->count - depth;
	if(start >= search->n || search->n - start < need)	{
		return;
	}
	minimum_sum = search->prefix[start + need] - search->prefix[start];
	maximum_sum = search->prefix[search->n] - search->prefix[search->n - need];
	if(remaining < minimum_sum || remaining > maximum_sum)	{
		return;
	}
	for(i = start;i + need <= search->n;i++)	{
		unsigned __int128 value = (unsigned __int128) search->items[i].value;
		unsigned __int128 after;
		if(value > remaining)	{
			break;
		}
		after = remaining - value;
		if(need > 1)	{
			unsigned __int128 minimum_after = search->prefix[i + need] - search->prefix[i + 1];
			unsigned __int128 maximum_after = search->prefix[search->n] - search->prefix[search->n - need + 1];
			if(after < minimum_after)	{
				break;
			}
			if(after > maximum_after)	{
				continue;
			}
		}
		else if(after != 0)	{
			continue;
		}
		search->chosen[depth] = search->items[i].index;
		enumerate_sum_subsets_recursive(search,i + 1,depth + 1,after);
	}
}

/*
	Report every set of count generated keys whose values (the
	sequential indexes or the normalised random offsets) add up
	to sum_value, return 0 when the needed memory can not be made
*/
static int enumerate_all_sum_subsets(struct search_state *state,uint64_t *values,uint64_t count,unsigned long int sum_value)	{
	struct sum_subset_search search;
	uint64_t i;
	search.state = state;
	search.n = state->n;
	search.count = count;
	search.items = (struct sum_subset_item*) calloc(state->n ? state->n : 1,sizeof(struct sum_subset_item));
	search.prefix = (unsigned __int128*) calloc((size_t) (state->n + 1),sizeof(unsigned __int128));
	search.chosen = (uint64_t*) calloc(count ? count : 1,sizeof(uint64_t));
	if(search.items == NULL || search.prefix == NULL || search.chosen == NULL)	{
		free(search.items);
		free(search.prefix);
		free(search.chosen);
		return 0;
	}
	for(i = 0;i < state->n;i++)	{
		search.items[i].value = values[i];
		search.items[i].index = i;
	}
	qsort(search.items,(size_t) state->n,sizeof(struct sum_subset_item),compare_sum_subset_items);
	search.prefix[0] = 0;
	for(i = 0;i < state->n;i++)	{
		search.prefix[i + 1] = search.prefix[i] + (unsigned __int128) search.items[i].value;
	}
	enumerate_sum_subsets_recursive(&search,0,0,(unsigned __int128) sum_value);
	free(search.items);
	free(search.prefix);
	free(search.chosen);
	return 1;
}

/*
	Search with sequential keys (base, base+1, ..., base+n-1).  The
	addition of count distinct sequential keys is
	(count * base + s) * G where s is the sum of count distinct
	offsets in [0, n-1], and every s between count*(count-1)/2 and
	count*(2n-count-1)/2 is possible, so for every count a BSGS
	search in that interval finds the only possible s, if any.
	This needs about sqrt(count * (n - count)) point operations per
	count instead of the combinations of a general search, so big
	-n values are usable, the cost only grows when no match with a
	small count exists and every count up to n must be searched.
*/
void search_sequential(struct search_state *state)	{
	struct Point remaining,temporary,negated_base;
	mpz_t minimum_sum,length,sum;
	uint64_t count,hits_before,i;
	int status;
	mpz_init(minimum_sum);
	mpz_init(length);
	mpz_init(sum);
	mpz_init(remaining.x);
	mpz_init(remaining.y);
	mpz_init(temporary.x);
	mpz_init(temporary.y);
	mpz_init(negated_base.x);
	mpz_init(negated_base.y);
	point_copy(&remaining,&target_publickey);
	point_negate_safe(&state->keys[0].publickey,&negated_base);
	fprintf(stderr,"[+] Search strategy: sequential offsets, a BSGS interval search is used for every number of keys from %llu to %llu\n",(unsigned long long) MIN_SUMMANDS,(unsigned long long) state->n);
	/* The loop below subtracts the base point once more for every count, so it must be subtracted MIN_SUMMANDS - 1 times before it starts */
	for(count = 1;count < MIN_SUMMANDS;count++)	{
		Point_Addition(&remaining,&negated_base,&temporary);
		point_copy(&remaining,&temporary);
	}
	for(count = MIN_SUMMANDS;count <= state->n;count++)	{
		uint64_t *indexes;
		Point_Addition(&remaining,&negated_base,&temporary);
		point_copy(&remaining,&temporary);
		mpz_set_ui(minimum_sum,(unsigned long int) count);
		mpz_mul_ui(minimum_sum,minimum_sum,(unsigned long int) (count - 1));
		mpz_fdiv_q_ui(minimum_sum,minimum_sum,2);
		mpz_set_ui(length,(unsigned long int) count);
		mpz_mul_ui(length,length,(unsigned long int) (state->n - count));
		status = bsgs_find_scalar(&remaining,minimum_sum,length,sum);
		if(status < 0)	{
			state->skipped++;
			fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, the BSGS table is over the limit of %llu entries, use -F to force it\n",(unsigned long long) count,(unsigned long long) SEARCH_ENTRY_LIMIT);
		}
		else if(status > 0)	{
			hits_before = state->hits;
			if(FLAG_MATCHALL && mpz_fits_ulong_p(sum))	{
				uint64_t *values = (uint64_t*) calloc(state->n,sizeof(uint64_t));
				if(values == NULL)	{
					fprintf(stderr,"[E] Error calloc, not enough memory to look for every addition of %llu generated publickeys\n",(unsigned long long) count);
				}
				else	{
					for(i = 0;i < state->n;i++)	{
						values[i] = i;
					}
					if(!enumerate_all_sum_subsets(state,values,count,mpz_get_ui(sum)))	{
						fprintf(stderr,"[E] Error calloc, not enough memory to look for every addition of %llu generated publickeys\n",(unsigned long long) count);
					}
					free(values);
				}
			}
			else	{
				if(FLAG_MATCHALL)	{
					fprintf(stderr,"[W] Every addition of %llu generated publickeys can not be enumerated, the offset sum does not fit in 64 bits, only one of them is reported\n",(unsigned long long) count);
				}
				indexes = sequential_indexes(state->n,count,sum,minimum_sum);
				if(indexes == NULL) {
					fprintf(stderr,"[E] The indexes of an addition of %llu generated publickeys can not be made\n",(unsigned long long) count);
				}
				else	{
					report_match(state,indexes,count);
					free(indexes);
				}
			}
			if(state->hits > hits_before && !FLAG_MATCHALL)	{
				break;
			}
		}
		if(isliveoutput())	{
			fprintf(stderr,"\r[+] searched additions of %llu generated publickeys, %llu of %llu numbers of keys",(unsigned long long) count,(unsigned long long) (count - MIN_SUMMANDS + 1),(unsigned long long) (state->n - MIN_SUMMANDS + 1));
			fflush(stderr);
		}
	}
	mpz_clear(minimum_sum);
	mpz_clear(length);
	mpz_clear(sum);
	mpz_clear(remaining.x);
	mpz_clear(remaining.y);
	mpz_clear(temporary.x);
	mpz_clear(temporary.y);
	mpz_clear(negated_base.x);
	mpz_clear(negated_base.y);
}

/*
	Bitsets of the sums that can be made with t of the offsets in
	offsets[l..r-1], dp[t] has the bit s set when s is one of them,
	GMP integers are used as the bitsets.
*/
static mpz_t *subset_dp_alloc(uint64_t max_count)	{
	mpz_t *dp;
	uint64_t i;
	dp = (mpz_t*) malloc((size_t) (max_count + 1) * sizeof(mpz_t));
	if(dp == NULL)	{
		return NULL;
	}
	for(i = 0;i <= max_count;i++)	{
		mpz_init_set_ui(dp[i],0);
	}
	mpz_setbit(dp[0],0);
	return dp;
}

static void subset_dp_free(mpz_t *dp,uint64_t max_count)	{
	uint64_t i;
	if(dp == NULL)	{
		return;
	}
	for(i = 0;i <= max_count;i++)	{
		mpz_clear(dp[i]);
	}
	free(dp);
}

static void subset_dp_compute(uint64_t *offsets,uint64_t l,uint64_t r,uint64_t max_count,mpz_t *dp)	{
	mpz_t shifted;
	uint64_t i,t,upper;
	mpz_init(shifted);
	for(i = l;i < r;i++)	{
		upper = i - l + 1;
		if(upper > max_count)	{
			upper = max_count;
		}
		for(t = upper;t >= 1;t--)	{
			mpz_mul_2exp(shifted,dp[t - 1],(mp_bitcnt_t) offsets[i]);
			mpz_ior(dp[t],dp[t],shifted);
		}
	}
	mpz_clear(shifted);
}

/*
	Find count offsets in offsets[l..r-1] with the given sum and
	write their positions in indexes, used only when a BSGS search
	already found that such a sum would make the target publickey,
	so it almost always finds one, the range is split in two and
	the bitsets of both halves say how the sum must be split.
*/
static int subset_dp_reconstruct(uint64_t *offsets,uint64_t l,uint64_t r,uint64_t count,unsigned long int sum,uint64_t *indexes,uint64_t *indexes_count)	{
	mpz_t *left_dp,*right_dp;
	uint64_t mid,left_count,right_count,first,last,chosen_left_count = 0;
	unsigned long int s,chosen_left_sum = 0;
	int found = 0;
	if(count == 0)	{
		return sum == 0;
	}
	if(r - l == 1)	{
		if(count == 1 && offsets[l] == sum)	{
			indexes[(*indexes_count)++] = l;
			return 1;
		}
		return 0;
	}
	mid = l + (r - l) / 2;
	left_dp = subset_dp_alloc(count);
	right_dp = subset_dp_alloc(count);
	if(left_dp == NULL || right_dp == NULL)	{
		subset_dp_free(left_dp,count);
		subset_dp_free(right_dp,count);
		return 0;
	}
	subset_dp_compute(offsets,l,mid,count,left_dp);
	subset_dp_compute(offsets,mid,r,count,right_dp);
	first = (count > r - mid) ? count - (r - mid) : 0;
	last = count < (mid - l) ? count : mid - l;
	for(left_count = first;left_count <= last && !found;left_count++)	{
		right_count = count - left_count;
		for(s = 0;s <= sum;s++)	{
			if(mpz_tstbit(left_dp[left_count],(mp_bitcnt_t) s) && mpz_tstbit(right_dp[right_count],(mp_bitcnt_t) (sum - s)))	{
				chosen_left_count = left_count;
				chosen_left_sum = s;
				found = 1;
				break;
			}
		}
	}
	subset_dp_free(left_dp,count);
	subset_dp_free(right_dp,count);
	if(!found)	{
		return 0;
	}
	if(!subset_dp_reconstruct(offsets,l,mid,chosen_left_count,chosen_left_sum,indexes,indexes_count))	{
		return 0;
	}
	return subset_dp_reconstruct(offsets,mid,r,count - chosen_left_count,sum - chosen_left_sum,indexes,indexes_count);
}

/*
	Approximation of C(n,k) for comparing search costs, it only
	needs the right order of magnitude, not an exact value
*/
static long double combination_estimate(uint64_t n,uint64_t k)	{
	long double result = 1.0L;
	uint64_t i;
	if(k > n)	{
		return 0.0L;
	}
	if(k > n - k)	{
		k = n - k;
	}
	for(i = 1;i <= k;i++)	{
		result = result * (long double) (n - k + i) / (long double) i;
	}
	return result;
}

/*
	Search with random keys when every offset fits in 64 bits and
	their span is small enough for a BSGS search: the addition of
	count distinct random keys is (count * (base + minimum offset)
	+ s) * G where s is the sum of count normalised offsets, a BSGS
	search finds the only possible s for every count and a subset
	sum reconstruction says which generated keys make that s.
	Return 1 when this strategy was used and -1 when it can not be
	used, then the general meet in the middle search must be used.
*/
int search_bounded_offsets(struct search_state *state)	{
	struct Point remaining,temporary,step,negated_step;
	mpz_t min_offset,max_offset,span,length,minimum_sum,sum,step_privatekey,first_count;
	uint64_t *offsets,count,i;
	int status;
	int result = 1;
	offsets = NULL;
	mpz_init(min_offset);
	mpz_init(max_offset);
	mpz_init(span);
	mpz_init(length);
	mpz_init(minimum_sum);
	mpz_init(sum);
	mpz_init(step_privatekey);
	mpz_init(first_count);
	mpz_set(min_offset,state->keys[0].offset);
	mpz_set(max_offset,state->keys[0].offset);
	for(i = 1;i < state->n;i++)	{
		if(mpz_cmp(state->keys[i].offset,min_offset) < 0)	{
			mpz_set(min_offset,state->keys[i].offset);
		}
		if(mpz_cmp(state->keys[i].offset,max_offset) > 0)	{
			mpz_set(max_offset,state->keys[i].offset);
		}
	}
	mpz_sub(span,max_offset,min_offset);
	if(!mpz_fits_ulong_p(min_offset) || !mpz_fits_ulong_p(span))	{
		result = -1;
		goto bounded_cleanup;
	}
	/*
		When even the smallest number of keys already needs a baby
		step table over the limit the general search is tried instead
	*/
	mpz_set_ui(first_count,(unsigned long int) MIN_SUMMANDS);
	mpz_mul(first_count,first_count,span);
	mpz_add_ui(first_count,first_count,1);
	mpz_sqrt(first_count,first_count);
	if(!mpz_fits_ulong_p(first_count) || (!FLAG_FORCESEARCH && (uint64_t) mpz_get_ui(first_count) > SEARCH_ENTRY_LIMIT))	{
		result = -1;
		goto bounded_cleanup;
	}
	/*
		When the general meet in the middle search can store the
		combinations of the smallest number of keys and it is
		cheaper than the baby steps of this search (a small -n
		with a very big offsets span, for example with -b 40),
		the general search is the better one for this run too
	*/
	{
		uint64_t left_count = MIN_SUMMANDS / 2;
		long double generic_cost = combination_estimate(state->n,left_count) + combination_estimate(state->n,MIN_SUMMANDS - left_count);
		long double bounded_cost = 2.0L * (long double) mpz_get_ui(first_count);
		if(generic_cost <= (long double) SEARCH_ENTRY_LIMIT && bounded_cost > generic_cost)	{
			result = -1;
			goto bounded_cleanup;
		}
	}
	offsets = (uint64_t*) calloc(state->n,sizeof(uint64_t));
	if(offsets == NULL)	{
		fprintf(stderr,"[E] Error calloc, not enough memory for the generated offsets\n");
		result = -1;
		goto bounded_cleanup;
	}
	for(i = 0;i < state->n;i++)	{
		mpz_sub(sum,state->keys[i].offset,min_offset);
		offsets[i] = (uint64_t) mpz_get_ui(sum);
	}
	mpz_init(step.x);
	mpz_init(step.y);
	mpz_init(negated_step.x);
	mpz_init(negated_step.y);
	mpz_init(remaining.x);
	mpz_init(remaining.y);
	mpz_init(temporary.x);
	mpz_init(temporary.y);
	mpz_add(step_privatekey,base_privatekey,min_offset);
	mpz_mod(step_privatekey,step_privatekey,EC.n);
	Scalar_Multiplication(G,&step,step_privatekey);
	point_negate_safe(&step,&negated_step);
	point_copy(&remaining,&target_publickey);
	gmp_fprintf(stderr,"[+] Search strategy: random offsets in a span of %Zd values, a BSGS search and a subset sum reconstruction are used for every number of keys from %llu to %llu\n",span,(unsigned long long) MIN_SUMMANDS,(unsigned long long) state->n);
	mpz_set_ui(minimum_sum,0);
	/* The loop below subtracts the step point once more for every count, so it must be subtracted MIN_SUMMANDS - 1 times before it starts */
	for(count = 1;count < MIN_SUMMANDS;count++)	{
		Point_Addition(&remaining,&negated_step,&temporary);
		point_copy(&remaining,&temporary);
	}
	for(count = MIN_SUMMANDS;count <= state->n;count++)	{
		uint64_t *indexes,indexes_count;
		Point_Addition(&remaining,&negated_step,&temporary);
		point_copy(&remaining,&temporary);
		mpz_set_ui(length,(unsigned long int) count);
		mpz_mul(length,length,span);
		status = bsgs_find_scalar(&remaining,minimum_sum,length,sum);
		if(status < 0)	{
			state->skipped++;
			fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, the BSGS table is over the limit of %llu entries, use -F to force it\n",(unsigned long long) count,(unsigned long long) SEARCH_ENTRY_LIMIT);
		}
		else if(status > 0)	{
			if(!mpz_fits_ulong_p(sum))	{
				state->skipped++;
				fprintf(stderr,"[W] Additions of %llu generated publickeys were not reconstructed, the offset sum does not fit in 64 bits\n",(unsigned long long) count);
			}
			else if(FLAG_MATCHALL)	{
				uint64_t hits_before = state->hits;
				if(!enumerate_all_sum_subsets(state,offsets,count,mpz_get_ui(sum)))	{
					fprintf(stderr,"[E] Error calloc, not enough memory to look for every addition of %llu generated publickeys\n",(unsigned long long) count);
				}
				if(state->hits > hits_before && !FLAG_MATCHALL)	{
					break;
				}
			}
			else	{
				indexes = (uint64_t*) calloc(count,sizeof(uint64_t));
				if(indexes == NULL)	{
					fprintf(stderr,"[E] Error calloc, not enough memory to report a match\n");
				}
				else	{
					uint64_t hits_before = state->hits;
					indexes_count = 0;
					if(subset_dp_reconstruct(offsets,0,state->n,count,mpz_get_ui(sum),indexes,&indexes_count) && indexes_count == count)	{
						report_match(state,indexes,count);
					}
					free(indexes);
					if(state->hits > hits_before && !FLAG_MATCHALL)	{
						break;
					}
				}
			}
		}
		if(isliveoutput())	{
			fprintf(stderr,"\r[+] searched additions of %llu generated publickeys, %llu of %llu numbers of keys",(unsigned long long) count,(unsigned long long) (count - MIN_SUMMANDS + 1),(unsigned long long) (state->n - MIN_SUMMANDS + 1));
			fflush(stderr);
		}
	}
	mpz_clear(step.x);
	mpz_clear(step.y);
	mpz_clear(negated_step.x);
	mpz_clear(negated_step.y);
	mpz_clear(remaining.x);
	mpz_clear(remaining.y);
	mpz_clear(temporary.x);
	mpz_clear(temporary.y);
bounded_cleanup:
	free(offsets);
	mpz_clear(min_offset);
	mpz_clear(max_offset);
	mpz_clear(span);
	mpz_clear(length);
	mpz_clear(minimum_sum);
	mpz_clear(sum);
	mpz_clear(step_privatekey);
	mpz_clear(first_count);
	return result;
}

typedef int (*combination_callback)(void *context,uint64_t *indexes,struct Point *point);

struct combination_enumerator	{
	struct generated_key *keys;
	uint64_t n;
	uint64_t choose;
	struct Point *path;
	uint64_t *indexes;
	combination_callback callback;
	void *callback_context;
	int stop;
};

static void enumerate_combinations_recursive(struct combination_enumerator *enumerator,uint64_t start,uint64_t depth)	{
	uint64_t i;
	if(enumerator->stop)	{
		return;
	}
	if(depth == enumerator->choose)	{
		if(enumerator->callback(enumerator->callback_context,enumerator->indexes,&enumerator->path[depth]))	{
			enumerator->stop = 1;
		}
		return;
	}
	for(i = start;i < enumerator->n;i++)	{
		if(enumerator->n - i < enumerator->choose - depth)	{
			break;
		}
		Point_Addition(&enumerator->path[depth],&enumerator->keys[i].publickey,&enumerator->path[depth + 1]);
		enumerator->indexes[depth] = i;
		enumerate_combinations_recursive(enumerator,i + 1,depth + 1);
		if(enumerator->stop)	{
			return;
		}
	}
}

/*
	Call the callback once for every set of choose distinct keys,
	with the indexes of the set and the addition of its publickeys,
	the additions are made while the sets are made so every set
	costs about one point addition per key over the shared path.
*/
static void enumerate_combinations(struct generated_key *keys,uint64_t n,uint64_t choose,combination_callback callback,void *callback_context)	{
	struct combination_enumerator enumerator;
	uint64_t i;
	enumerator.keys = keys;
	enumerator.n = n;
	enumerator.choose = choose;
	enumerator.callback = callback;
	enumerator.callback_context = callback_context;
	enumerator.stop = 0;
	enumerator.path = (struct Point*) calloc((size_t) (choose + 1),sizeof(struct Point));
	enumerator.indexes = (uint64_t*) calloc(choose ? (size_t) choose : 1,sizeof(uint64_t));
	if(enumerator.path == NULL || enumerator.indexes == NULL)	{
		fprintf(stderr,"[E] Error calloc, not enough memory to enumerate combinations of keys\n");
		free(enumerator.path);
		free(enumerator.indexes);
		return;
	}
	for(i = 0;i <= choose;i++)	{
		mpz_init_set_ui(enumerator.path[i].x,0);
		mpz_init_set_ui(enumerator.path[i].y,0);
	}
	enumerate_combinations_recursive(&enumerator,0,0);
	for(i = 0;i <= choose;i++)	{
		mpz_clear(enumerator.path[i].x);
		mpz_clear(enumerator.path[i].y);
	}
	free(enumerator.path);
	free(enumerator.indexes);
}

struct subset_table	{
	struct subset_slot *slots;
	uint32_t *indexes;
	uint64_t mask;
	uint64_t keys_per_sum;
};

static int subset_insert_callback(void *context,uint64_t *indexes,struct Point *point)	{
	struct subset_table *table = (struct subset_table*) context;
	char str_x[65];
	uint64_t position,i;
	gmp_snprintf(str_x,sizeof(str_x),"%064Zx",point->x);
	position = hash_x(str_x) & table->mask;
	while(table->slots[position].used)	{
		position = (position + 1) & table->mask;
	}
	memcpy(table->slots[position].x,str_x,65);
	table->slots[position].odd = (uint8_t) mpz_tstbit(point->y,0);
	table->slots[position].used = 1;
	for(i = 0;i < table->keys_per_sum;i++)	{
		table->indexes[position * table->keys_per_sum + i] = (uint32_t) indexes[i];
	}
	return 0;
}

struct subset_lookup	{
	struct subset_table *table;
	struct Point *point;
	struct Point negated;
	struct Point difference;
	struct search_state *state;
	uint64_t left_count;
	uint64_t right_count;
	int complement;
	int stop;
};

static int compare_uint64(const void *a,const void *b)	{
	uint64_t left = *((const uint64_t*) a);
	uint64_t right = *((const uint64_t*) b);
	if(left < right)	{
		return -1;
	}
	if(left > right)	{
		return 1;
	}
	return 0;
}

static int subset_lookup_callback(void *context,uint64_t *indexes,struct Point *point)	{
	struct subset_lookup *lookup = (struct subset_lookup*) context;
	char str_x[65];
	uint64_t position,i,j;
	point_negate_safe(point,&lookup->negated);
	Point_Addition(lookup->point,&lookup->negated,&lookup->difference);
	gmp_snprintf(str_x,sizeof(str_x),"%064Zx",lookup->difference.x);
	position = hash_x(str_x) & lookup->table->mask;
	while(lookup->table->slots[position].used && !lookup->stop)	{
		if(lookup->table->slots[position].odd == (uint8_t) mpz_tstbit(lookup->difference.y,0) && strcmp(lookup->table->slots[position].x,str_x) == 0)	{
			uint32_t *left_indexes = lookup->table->keys_per_sum ? lookup->table->indexes + position * lookup->table->keys_per_sum : NULL;
			int disjoint = 1;
			for(i = 0;i < lookup->left_count && disjoint;i++)	{
				for(j = 0;j < lookup->right_count;j++)	{
					if((uint64_t) left_indexes[i] == indexes[j])	{
						disjoint = 0;
						break;
					}
				}
			}
			if(disjoint)	{
				uint64_t sum_count = lookup->left_count + lookup->right_count;
				uint64_t *combined = (uint64_t*) calloc(sum_count ? sum_count : 1,sizeof(uint64_t));
				if(combined == NULL)	{
					fprintf(stderr,"[E] Error calloc, not enough memory to report a match\n");
				}
				else	{
					uint64_t hits_before = lookup->state->hits;
					for(i = 0;i < lookup->left_count;i++)	{
						combined[i] = (uint64_t) left_indexes[i];
					}
					for(i = 0;i < lookup->right_count;i++)	{
						combined[lookup->left_count + i] = indexes[i];
					}
					qsort(combined,(size_t) sum_count,sizeof(uint64_t),compare_uint64);
					if(lookup->complement)	{
						uint64_t *actual = (uint64_t*) calloc(lookup->state->n - sum_count ? lookup->state->n - sum_count : 1,sizeof(uint64_t));
						if(actual == NULL)	{
							fprintf(stderr,"[E] Error calloc, not enough memory to report a match\n");
						}
						else	{
							uint64_t actual_count = 0,p = 0,key_index;
							for(key_index = 0;key_index < lookup->state->n;key_index++)	{
								if(p < sum_count && combined[p] == key_index)	{
									p++;
								}
								else	{
									actual[actual_count++] = key_index;
								}
							}
							report_match(lookup->state,actual,actual_count);
							free(actual);
						}
					}
					else	{
						report_match(lookup->state,combined,sum_count);
					}
					free(combined);
					if(lookup->state->hits > hits_before && !FLAG_MATCHALL)	{
						lookup->stop = 1;
					}
				}
			}
		}
		position = (position + 1) & lookup->table->mask;
	}
	return lookup->stop;
}

/*
	General search, used for random keys whose offsets span is too
	big for the BSGS search: for every number of keys count, split
	count in two halves, store the additions of every set of the
	first half, then look for target minus the addition of every
	set of the second half in that table, the two sets must not
	share a key.  When count is over n/2 the same is done with the
	complement set, additions of count keys are additions of all
	the keys minus additions of n - count keys.
	The number of stored combinations is C(n, count/2), it can be
	far too big for a big -n (finding additions of at least 10 keys
	in a general set is a subset sum problem, no exact search can
	do that fast for every -n), then that number of keys is skipped
	and reported, it is not searched, unless -F is used.
*/
void search_meet_in_the_middle(struct search_state *state)	{
	struct Point total,temporary,transformed,negated_target;
	struct subset_table table;
	struct subset_lookup lookup;
	mpz_t combinations;
	uint64_t count,i;
	fprintf(stderr,"[+] Search strategy: meet in the middle, the combinations of half of every number of keys are stored in memory\n");
	mpz_init(combinations);
	mpz_init(total.x);
	mpz_init(total.y);
	mpz_init(temporary.x);
	mpz_init(temporary.y);
	mpz_init(transformed.x);
	mpz_init(transformed.y);
	mpz_init(negated_target.x);
	mpz_init(negated_target.y);
	mpz_set_ui(total.x,0);
	mpz_set_ui(total.y,0);
	for(i = 0;i < state->n;i++)	{
		Point_Addition(&total,&state->keys[i].publickey,&temporary);
		point_copy(&total,&temporary);
	}
	point_negate_safe(&target_publickey,&negated_target);
	for(count = MIN_SUMMANDS;count <= state->n && !(state->hits > 0 && !FLAG_MATCHALL);count++)	{
		uint64_t sum_count,left_count,right_count,table_size,ram_needed,ram_total,hits_before;
		int complement;
		complement = (state->n - count < count);
		sum_count = complement ? state->n - count : count;
		if(complement)	{
			Point_Addition(&total,&negated_target,&transformed);
		}
		else	{
			point_copy(&transformed,&target_publickey);
		}
		if(sum_count == 0)	{
			if(point_is_infinity(&transformed))	{
				uint64_t *indexes = (uint64_t*) calloc(state->n,sizeof(uint64_t));
				if(indexes == NULL)	{
					fprintf(stderr,"[E] Error calloc, not enough memory to report a match\n");
				}
				else	{
					for(i = 0;i < state->n;i++)	{
						indexes[i] = i;
					}
					report_match(state,indexes,state->n);
					free(indexes);
				}
			}
			continue;
		}
		left_count = sum_count / 2;
		right_count = sum_count - left_count;
		mpz_bin_uiui(combinations,(unsigned long int) state->n,(unsigned long int) left_count);
		if(!mpz_fits_ulong_p(combinations) || mpz_cmp_ui(combinations,(unsigned long int) (UINT64_MAX / 2)) > 0)	{
			state->skipped++;
			gmp_fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, they need %Zd combinations and the table size overflows\n",(unsigned long long) count,combinations);
			continue;
		}
		if(!FLAG_FORCESEARCH && (uint64_t) mpz_get_ui(combinations) > SEARCH_ENTRY_LIMIT)	{
			state->skipped++;
			gmp_fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, they need %Zd combinations over the limit of %llu, use -F to force it\n",(unsigned long long) count,combinations,(unsigned long long) SEARCH_ENTRY_LIMIT);
			continue;
		}
		table_size = 1024;
		while(table_size < (uint64_t) mpz_get_ui(combinations) * 2)	{
			if(table_size > (UINT64_MAX / 2))	{
				table_size = 0;
				break;
			}
			table_size <<= 1;
		}
		if(table_size == 0)	{
			state->skipped++;
			fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, the table size overflows\n",(unsigned long long) count);
			continue;
		}
		if(table_size > UINT64_MAX / (sizeof(struct subset_slot) + left_count * sizeof(uint32_t)))	{
			state->skipped++;
			fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, the table size overflows\n",(unsigned long long) count);
			continue;
		}
		ram_needed = table_size * (sizeof(struct subset_slot) + left_count * sizeof(uint32_t));
		ram_total = system_ram();
		if(!FLAG_FORCESEARCH && ram_total > 0 && ram_needed > ram_total)	{
			char str_bytes[64];
			format_bytes(ram_needed,str_bytes,sizeof(str_bytes));
			state->skipped++;
			fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, the table needs %s (%llu bytes) over the system RAM, use -F to force it\n",(unsigned long long) count,str_bytes,(unsigned long long) ram_needed);
			continue;
		}
		table.slots = (struct subset_slot*) calloc(table_size,sizeof(struct subset_slot));
		table.indexes = left_count ? (uint32_t*) calloc(table_size * (size_t) left_count,sizeof(uint32_t)) : NULL;
		if(table.slots == NULL || (left_count && table.indexes == NULL))	{
			char str_bytes[64];
			format_bytes(ram_needed,str_bytes,sizeof(str_bytes));
			state->skipped++;
			fprintf(stderr,"[W] Additions of %llu generated publickeys were not searched, not enough memory for the table, %s (%llu bytes) are needed\n",(unsigned long long) count,str_bytes,(unsigned long long) ram_needed);
			free(table.slots);
			free(table.indexes);
			continue;
		}
		table.mask = table_size - 1;
		table.keys_per_sum = left_count;
		hits_before = state->hits;
		enumerate_combinations(state->keys,state->n,left_count,subset_insert_callback,&table);
		lookup.table = &table;
		lookup.point = &transformed;
		lookup.state = state;
		lookup.left_count = left_count;
		lookup.right_count = right_count;
		lookup.complement = complement;
		lookup.stop = 0;
		mpz_init(lookup.negated.x);
		mpz_init(lookup.negated.y);
		mpz_init(lookup.difference.x);
		mpz_init(lookup.difference.y);
		enumerate_combinations(state->keys,state->n,right_count,subset_lookup_callback,&lookup);
		mpz_clear(lookup.negated.x);
		mpz_clear(lookup.negated.y);
		mpz_clear(lookup.difference.x);
		mpz_clear(lookup.difference.y);
		free(table.slots);
		free(table.indexes);
		if(state->hits > hits_before && !FLAG_MATCHALL)	{
			break;
		}
		if(isliveoutput())	{
			fprintf(stderr,"\r[+] searched additions of %llu generated publickeys, %llu of %llu numbers of keys",(unsigned long long) count,(unsigned long long) (count - MIN_SUMMANDS + 1),(unsigned long long) (state->n - MIN_SUMMANDS + 1));
			fflush(stderr);
		}
	}
	mpz_clear(combinations);
	mpz_clear(total.x);
	mpz_clear(total.y);
	mpz_clear(temporary.x);
	mpz_clear(temporary.y);
	mpz_clear(transformed.x);
	mpz_clear(transformed.y);
	mpz_clear(negated_target.x);
	mpz_clear(negated_target.y);
}

/*
	Generate N public/privatekey pairs from one base privatekey and
	check if the publickey given by the user (-p) is the addition of
	MIN_SUMMANDS (10 by default, set with -m) or more of the
	generated publickeys, every generated publickey can be used only
	once in that addition.  The privatekey of the -p publickey is
	then the addition of the privatekeys that produced it and it is
	printed verified.
	The keys are generated sequentially (basekey, basekey+1,
	basekey+2, ...) or with a random offset when -R is used.
	The generated keys are never stored in a file, they are just
	printed to the stdout while they are generated, in memory every
	generated key is kept to be able to search for the additions.
	All the keys are generated before the search, a match can use
	any of the generated keys, also the last ones.
*/
void generate_and_match()	{
	struct match_slot *table;
	struct generated_key *keys = NULL;
	struct search_state search;
	struct Point generated_publickey;
	char str_x[65],str_privatekey[65],str_publicdata[132],str_bytes[64];
	mpz_t offset,privatekey,random_range;
	uint64_t i,count = 0,table_size = 1024,mask,progress,ram_needed = 0;
	uint8_t odd;
	int duplicated;
	clock_t begin;
	if(!FLAG_PUBLIC)	{
		fprintf(stderr,"[E] The -p publickey is required to check it against additions of the generated publickeys\n");
		exit(0);
	}
	if(!FLAG_N || N == 0)	{
		fprintf(stderr,"[E] The -n number of keys to generate is required\n");
		exit(0);
	}
	mpz_init(offset);
	mpz_init(privatekey);
	mpz_init(random_range);
	mpz_init(generated_publickey.x);
	mpz_init(generated_publickey.y);
	while(table_size < (N * 2))	{
		table_size <<= 1;
		if(table_size == 0)	{
			fprintf(stderr,"[E] Too many keys requested: %llu\n",(unsigned long long) N);
			exit(0);
		}
	}
	/*
		The RAM needed is the table used to avoid repeated random
		keys while they are generated plus every generated key,
		which is kept in memory for the search, the search can
		need more tables of its own and reports them by itself
	*/
	if(N > (UINT64_MAX - table_size * sizeof(struct match_slot)) / (sizeof(struct generated_key) + 128))	{
		fprintf(stderr,"[E] Too many keys requested: %llu, the size of the tables overflows\n",(unsigned long long) N);
		exit(0);
	}
	ram_needed = table_size * sizeof(struct match_slot) + N * (sizeof(struct generated_key) + 128);
	format_bytes(ram_needed,str_bytes,sizeof(str_bytes));
	fprintf(stderr,"[+] Estimated RAM needed: %s (%llu bytes), %llu bytes per slot for %llu slots plus the %llu generated keys kept in memory\n",str_bytes,(unsigned long long) ram_needed,(unsigned long long) sizeof(struct match_slot),(unsigned long long) table_size,(unsigned long long) N);
	show_system_ram(ram_needed);
	keys = (struct generated_key*) calloc(N,sizeof(struct generated_key));
	if(keys == NULL)	{
		format_bytes(ram_needed,str_bytes,sizeof(str_bytes));
		fprintf(stderr,"[E] Error calloc, not enough memory to keep %llu keys, %s (%llu bytes) are needed\n",(unsigned long long) N,str_bytes,(unsigned long long) ram_needed);
		exit(0);
	}
	for(i = 0;i < N;i++)	{
		mpz_init(keys[i].privatekey);
		mpz_init(keys[i].offset);
		mpz_init(keys[i].publickey.x);
		mpz_init(keys[i].publickey.y);
	}
	table = (struct match_slot*) calloc(table_size,sizeof(struct match_slot));
	if(table == NULL)	{
		format_bytes(ram_needed,str_bytes,sizeof(str_bytes));
		fprintf(stderr,"[E] Error calloc, not enough memory to index %llu keys, %s (%llu bytes) are needed\n",(unsigned long long) N,str_bytes,(unsigned long long) ram_needed);
		exit(0);
	}
	mask = table_size - 1;

	gmp_fprintf(stderr,"[+] Base privatekey: %064Zx\n",base_privatekey);
	fprintf(stderr,"[+] Keys to generate and check: %llu\n",(unsigned long long) N);
	fprintf(stderr,"[+] Minimum number of distinct generated publickeys to add: %llu\n",(unsigned long long) MIN_SUMMANDS);
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
		mpz_set(keys[i].privatekey,privatekey);
		mpz_set(keys[i].offset,offset);
		point_copy(&keys[i].publickey,&generated_publickey);
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
		match_add(table,mask,str_x,str_privatekey,odd,i);
		if((count % progress) == 0)	{
			show_progress(count,N);
		}
	}
	free(table);
	table = NULL;

	memset(&search,0,sizeof(search));
	search.keys = keys;
	search.n = N;
	fprintf(stderr,"%s[+] Searching if the target publickey is the addition of %llu or more distinct generated publickeys\n",isliveoutput() ? "\r" : "",(unsigned long long) MIN_SUMMANDS);
	if(MIN_SUMMANDS > N)	{
		fprintf(stderr,"[-] No match: %llu distinct generated publickeys are needed but only %llu were generated\n",(unsigned long long) MIN_SUMMANDS,(unsigned long long) N);
	}
	else if(!FLAG_RANDOM)	{
		search_sequential(&search);
	}
	else if(search_bounded_offsets(&search) < 0)	{
		search_meet_in_the_middle(&search);
	}
	fprintf(stderr,"%s[+] %llu keys generated and checked in %.2f seconds\n",isliveoutput() ? "\r" : "",(unsigned long long) count,(double) (clock() - begin) / CLOCKS_PER_SEC);
	if(search.hits == 0 && MIN_SUMMANDS <= N)	{
		if(search.skipped == 0)	{
			fprintf(stderr,"[-] No match: the target publickey is not the addition of %llu or more of the generated publickeys\n",(unsigned long long) MIN_SUMMANDS);
		}
		else	{
			fprintf(stderr,"[-] No match found in the searched numbers of keys: the target publickey can still be the addition of %llu or more of the generated publickeys, %llu numbers of keys were not searched because their search is too big, use -F to force them or a lower -n\n",(unsigned long long) MIN_SUMMANDS,(unsigned long long) search.skipped);
		}
	}
	else if(search.skipped > 0 && FLAG_MATCHALL)	{
		fprintf(stderr,"[W] %llu numbers of keys were not searched because their search is too big, more matches can exist, use -F to force them\n",(unsigned long long) search.skipped);
	}
	search_state_free_reported(&search);
	for(i = 0;i < N;i++)	{
		mpz_clear(keys[i].privatekey);
		mpz_clear(keys[i].offset);
		mpz_clear(keys[i].publickey.x);
		mpz_clear(keys[i].publickey.y);
	}
	free(keys);
	mpz_clear(offset);
	mpz_clear(privatekey);
	mpz_clear(random_range);
	mpz_clear(generated_publickey.x);
	mpz_clear(generated_publickey.y);
}
