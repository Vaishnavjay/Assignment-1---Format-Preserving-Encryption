#include <stdint.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <ctype.h>
/*
 * Data Encryption Standard
 * An approach to DES algorithm
 *
 * By: Daniel Huertas Gonzalez
 * Email: huertas.dani@gmail.com
 * Version: 0.1
 *
 * Based on the document FIPS PUB 46-3
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define LB32_MASK   0x00000001
#define LB64_MASK   0x0000000000000001
#define L64_MASK    0x00000000ffffffff
#define H64_MASK    0xffffffff00000000

/* Initial Permutation Table */
static char IP[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

/* Inverse Initial Permutation Table */
static char PI[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

/*Expansion table */
static char E[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

/* Post S-Box permutation */
static char P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

/* The S-Box tables */
static char S[8][64] = {{
    /* S1 */
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
},{
    /* S2 */
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
},{
    /* S3 */
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
},{
    /* S4 */
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
},{
    /* S5 */
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
},{
    /* S6 */
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
},{
    /* S7 */
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
},{
    /* S8 */
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
}};

/* Permuted Choice 1 Table */
static char PC1[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,

    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

/* Permuted Choice 2 Table */
static char PC2[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

/* Iteration Shift Array */
static char iteration_shift[] = {
 /* 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16 */
    1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
};

/*
 * The DES function
 * input: 64 bit message
 * key: 64 bit key for encryption/decryption
 * mode: 'e' = encryption; 'd' = decryption
 */
uint64_t des(uint64_t input, uint64_t key, char mode) {

    int i, j;

    /* 8 bits */
    char row, column;

    /* 28 bits */
    uint32_t C                  = 0;
    uint32_t D                  = 0;

    /* 32 bits */
    uint32_t L                  = 0;
    uint32_t R                  = 0;
    uint32_t s_output           = 0;
    uint32_t f_function_res     = 0;
    uint32_t temp               = 0;

    /* 48 bits */
    uint64_t sub_key[16]        = {0};
    uint64_t s_input            = 0;

    /* 56 bits */
    uint64_t permuted_choice_1  = 0;
    uint64_t permuted_choice_2  = 0;

    /* 64 bits */
    uint64_t init_perm_res      = 0;
    uint64_t inv_init_perm_res  = 0;
    uint64_t pre_output         = 0;

    /* initial permutation */
    for (i = 0; i < 64; i++) {

        init_perm_res <<= 1;
        init_perm_res |= (input >> (64-IP[i])) & LB64_MASK;

    }

    L = (uint32_t) (init_perm_res >> 32) & L64_MASK;
    R = (uint32_t) init_perm_res & L64_MASK;

    /* initial key schedule calculation */
    for (i = 0; i < 56; i++) {

        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (key >> (64-PC1[i])) & LB64_MASK;

    }

    C = (uint32_t) ((permuted_choice_1 >> 28) & 0x000000000fffffff);
    D = (uint32_t) (permuted_choice_1 & 0x000000000fffffff);

    /* Calculation of the 16 keys */
    for (i = 0; i< 16; i++) {

        /* key schedule */
        // shifting Ci and Di
        for (j = 0; j < iteration_shift[i]; j++) {

            C = 0x0fffffff & (C << 1) | 0x00000001 & (C >> 27);
            D = 0x0fffffff & (D << 1) | 0x00000001 & (D >> 27);

        }

        permuted_choice_2 = 0;
        permuted_choice_2 = (((uint64_t) C) << 28) | (uint64_t) D ;

        sub_key[i] = 0;

        for (j = 0; j < 48; j++) {

            sub_key[i] <<= 1;
            sub_key[i] |= (permuted_choice_2 >> (56-PC2[j])) & LB64_MASK;
        }
    }
    for (i = 0; i < 16; i++) {
        /* f(R,k) function */
        s_input = 0;

        for (j = 0; j< 48; j++) {

            s_input <<= 1;
            s_input |= (uint64_t) ((R >> (32-E[j])) & LB32_MASK);

        }

        /*
         * Encryption/Decryption
         * XORing expanded Ri with Ki
         */
        if (mode == 'd') {
            // decryption
            s_input = s_input ^ sub_key[15-i];

        } else {
            // encryption
            s_input = s_input ^ sub_key[i];

        }

        /* S-Box Tables */
        for (j = 0; j < 8; j++) {
            // 00 00 RCCC CR00 00 00 00 00 00 s_input
            // 00 00 1000 0100 00 00 00 00 00 row mask
            // 00 00 0111 1000 00 00 00 00 00 column mask

            row = (char) ((s_input & (0x0000840000000000 >> 6*j)) >> 42-6*j);
            row = (row >> 4) | row & 0x01;

            column = (char) ((s_input & (0x0000780000000000 >> 6*j)) >> 43-6*j);

            s_output <<= 4;
            s_output |= (uint32_t) (S[j][16*row + column] & 0x0f);

        }

        f_function_res = 0;

        for (j = 0; j < 32; j++) {

            f_function_res <<= 1;
            f_function_res |= (s_output >> (32 - P[j])) & LB32_MASK;

        }

        temp = R;
        R = L ^ f_function_res;
        L = temp;

    }

    pre_output = (((uint64_t) R) << 32) | (uint64_t) L;

    /* inverse initial permutation */
    for (i = 0; i < 64; i++) {

        inv_init_perm_res <<= 1;
        inv_init_perm_res |= (pre_output >> (64-PI[i])) & LB64_MASK;

    }

    return inv_init_perm_res;

}
int bintohex(int num){
    int i=1;
    int r;
    int hex=0;
    while (num != 0)
    {
        r = num % 10;
        hex = hex + r * i;
        i = i * 2;
        num = num / 10;
    }
    return hex;
}
long long int concat(long long int a, long long int b)
{
    char s1[20];
    char s2[20];

    sprintf(s1, "%lld", a);
    sprintf(s2, "%lld", b);
    strcat(s1, s2);
    long long int c = atoll(s1);
    return c;
}
struct arrWrap {
    char hexnum[10];
};
struct arrWrap dectohex(int num)
{
    struct arrWrap x;
    int decnum, rem, i=0;
    decnum = num;

    while(decnum!=0)
    {
        rem = decnum%16;
        if(rem<10)
            rem = rem+48;
        else
            rem = rem+55;
        x.hexnum[i] = rem;
        i++;
        decnum = decnum/16;
    }

    return x;
 }
 struct arrbin {
    int binnum[10];
};
struct arrbin dectobin(int num)
{
    struct arrbin x;
    int n, i=0,k;
    n = num;
    for(i=0;n>0;i++)
    {
        x.binnum[i]=n%2;
        n=n/2;
    }
    for(k=i;k<10;k++){
        x.binnum[k] = 0;
    }

    return x;
 }
 void encrypt (){
    unsigned long long inp,inp1;
    printf("Enter the 16 digit credit card number : \n ");
    scanf("%lld", &inp);
    int count=0;   // variable declaration
    inp1 = inp;
    while(inp1!=0)
    {
       inp1=inp1/10;
       count++;
    }
    if (count !=16){
        printf("Please enter 16 digit credit card number");
        return;
    }
    int iin[6];
    int data[6];
    int tin[4];
    int tweak[6];
    int tweak_num[6];
    int arr[16];
    int arr1[16];
    int i = 0;
    int j, r;
    inp1 = inp;
    while (inp1 != 0) {
        r = inp1 % 10;
        arr[i] = r;
        i++;
        inp1 = inp1 / 10;
    }
    r=0;
    for (j = i - 1; j > -1; j--) {
        arr1[r] = arr[j];
        r++;
    }
    r=0;
    for (j=5;j>=0;j--) {
        iin[r] = arr1[j];
        r++;
    }
    r=0;
    for (j=11;j>=6;j--) {
        data[r] = arr1[j];
        r++;
    }
    r=0;
    tweak[5] = iin[5];
    tweak[4] = iin[4];
    for (j=15;j>=12;j--) {
        tin[r] = arr1[j];
        tweak[r] = arr1[j];
        r++;
    }
    for (j=5;j>=0;j--) {
        tweak_num[j] = (data[j] + tweak[j]) % 10;
    }
    uint64_t key = 0x0E329232EA6D0D73;
    printf ("\nKey used for DES encryption = %llx",key);
    printf ("\nIssue Identification Number = ");
    for (j=5;j>=0;j--) {
        printf("%d",iin[j]);
    }
    printf ("\nData to be encrypted = ");
    for (j=5;j>=0;j--) {
        printf("%d",data[j]);
    }
    printf ("\nTransaction Identification Number = ");
    for (j=3;j>=0;j--) {
        printf("%d",tin[j]);
    }
    printf ("\nTweak = ");
    for (j=5;j>=0;j--) {
        printf("%d",tweak[j]);
    }
    printf ("\nTweaked number = ");
    for (j=5;j>=0;j--) {
        printf("%d",tweak_num[j]);
    }
    int twk_num = 0;
    int b=1,k;
    for (j=0;j<6;j++) {
        twk_num = (b* tweak_num[j])+ twk_num;
        b*=10;
    }
    int tweak_bin[20];
    int left[10], right[10];
    for(j=0;twk_num>0;j++)
    {
        tweak_bin[j]=twk_num%2;
        twk_num=twk_num/2;
    }
    printf("\nBinary form of tweaked num = ");
    for(k=j;k<20;k++){
        tweak_bin[k] = 0;
    }
    for(j=19;j>=0;j--)
    {
        printf("%d",tweak_bin[j]);
    }
    for(j=0;j<10;j++)
    {
        right[j] = tweak_bin[j];
        left[j] = tweak_bin[j+10];
    }
    int left_num=0, right_num=0;
    b=1;
    for (j=0;j<10;j++) {
        left_num = (b* left[j])+ left_num;
        right_num = (b* right[j])+ right_num;
        b*=10;
    }
    printf("\nLeft half = %d",left_num);
    printf("\nRight half = %d",right_num);

    uint64_t input;
    uint64_t result_enc, result_dec;
    int result_enc_trunc, result_dec_trunc;
    struct arrWrap x;
    printf("\n\nEncryption Round 0");
    printf("\nLeft half = %d",bintohex(left_num));
    printf("\nRight half = %d",bintohex(right_num));
    left_num = bintohex(left_num);
    right_num = bintohex(right_num);
    for (i = 0; i < 16; i++) {
        if (i%2 == 0) {
            input = right_num;
            result_enc = des(input, key, 'e');
            result_enc_trunc = result_enc & 0x000000000000fff;
            do {
            left_num = left_num ^ result_enc_trunc;
            }while(left_num>999);
        } else {

            input = left_num;
            result_enc = des(input, key, 'e');
            result_enc_trunc = result_enc & 0x000000000000fff;
            do {
            right_num = right_num ^ result_enc_trunc;
            }while(right_num>999);
        }
        printf("\n\nEncryption Round %d",(i+1));
        if(i==0){
            printf("\nLeft half = %d",left_num);
            printf("\nRight half = %d",right_num);
        }
        else{
            printf("\nLeft half = %d",left_num);
            printf("\nRight half = %d",right_num);
        }

        printf ("\nOutput of Fk: %016llx", result_enc);

    }
    int left_num_arr[3], right_num_arr[3];
    if (left_num<10){
        left_num_arr[0] = left_num % 10;
        left_num_arr[1] = 0;
        left_num_arr[2] = 0;
    }
    else if (left_num<100){
        left_num_arr[0] = left_num % 10;
        left_num_arr[1] = (left_num/10) % 10;
        left_num_arr[2] = 0;
    }
    else{
        left_num_arr[0] = left_num % 10;
        left_num_arr[1] = (left_num/10) % 10;
        left_num_arr[2] = (left_num/100) % 10;
    }
    if (right_num<10){
        right_num_arr[0] =right_num % 10;
        right_num_arr[1] = 0;
        right_num_arr[2] = 0;
    }
    else if (right_num<100){
        right_num_arr[0] = right_num % 10;
        right_num_arr[1] = (right_num/10) % 10;
        right_num_arr[2] = 0;
    }
    else{
        right_num_arr[0] = right_num % 10;
        right_num_arr[1] = (right_num/10) % 10;
        right_num_arr[2] = (right_num/100) % 10;
    }
    int enc_out[16];
    r=0;
    for (j = 15; j > 11; j--) {
            enc_out[r] = arr1[j];
            r++;
    }
    for (j = 0; j < 3; j++) {
            enc_out[r] = right_num_arr[j];
            r++;
    }
    for (j = 0; j < 3; j++) {
            enc_out[r] = left_num_arr[j];
            r++;
    }
    for (j = 5; j >= 0; j--) {
            enc_out[r] = arr1[j];
            r++;
    }
    printf("\n\nEncrypted Output = ");
    for (j = 15; j >=0; j--) {
        printf("%d",enc_out[j]);
    }
 }
void decrypt() {
    unsigned long long inp,inp1;
    printf("Enter the 16 digit encrypted card number : \n ");
    scanf("%lld", &inp);
    //printf("The number is : %lld",inp);
    int count=0;   // variable declaration
    inp1 = inp;
    while(inp1!=0)
    {
       inp1=inp1/10;
       count++;
    }
    if (count !=16){
        printf("Please enter a 16 digit number");
        return;
    }
    int iin[6];
    int data[6];
    int tin[4];
    int tweak[6];
    int tweak_num[6];
    int arr[16];
    int arr1[16];
    int i = 0;
    int j, r;
    inp1 = inp;
    while (inp1 != 0) {
        r = inp1 % 10;
        arr[i] = r;
        i++;
        inp1 = inp1 / 10;
    }
    r=0;
    for (j = i - 1; j > -1; j--) {
        arr1[r] = arr[j];
        r++;
    }
    r=0;
    for (j=5;j>=0;j--) {
        iin[r] = arr1[j];
        r++;
    }
    r=0;
    for (j=11;j>=6;j--) {
        data[r] = arr1[j];
        r++;
    }
    r=0;
    tweak[5] = iin[5];
    tweak[4] = iin[4];
    for (j=15;j>=12;j--) {
        tin[r] = arr1[j];
        tweak[r] = arr1[j];
        r++;
    }
    uint64_t key = 0x0E329232EA6D0D73;
    printf ("\nKey used for DES encryption = %llx",key);
    printf ("\nIssue Identification Number = ");
    for (j=5;j>=0;j--) {
        printf("%d",iin[j]);
    }
    printf ("\nEncrypted data = ");
    for (j=5;j>=0;j--) {
        printf("%d",data[j]);
    }
    printf ("\nTransaction Identification Number = ");
    for (j=3;j>=0;j--) {
        printf("%d",tin[j]);
    }
    int data_num = 0, data_num1;
    int b=1,k;
    for (j=0;j<6;j++) {
        data_num = (b* data[j])+ data_num;
        b*=10;
    }
    //printf("\n Data num %d ",data_num);
    int data_bin[20];
    int left[10], right[10];
    data_num1 = data_num;
    for(j=0;data_num1>0;j++)
    {
        data_bin[j]=data_num1%2;
        data_num1=data_num1/2;
    }

    for(k=j;k<20;k++){
        data_bin[k] = 0;
    }

    int left_num=0, right_num=0;
    right_num = data_num % 1000;
    left_num = data_num / 1000;
    printf("\nLeft half = %d",left_num);
    printf("\nRight half = %d",right_num);

    uint64_t input;
    uint64_t result_enc, result_dec;
    int result_enc_trunc, result_dec_trunc;
    struct arrWrap x;


    printf("\n\nDecryption Round 0");
    printf("\nLeft half = %d",left_num);
    printf("\nRight half = %d",right_num);
    for (i = 0; i < 16; i++) {
        if (i%2 != 0) {
            input = right_num;
            result_dec = des(input, key, 'e');
            result_dec_trunc = result_dec & 0x000000000000fff;
            do {
                left_num = left_num ^ result_dec_trunc;
            }while(left_num>999);
        } else {

            input = left_num;
            result_enc = des(input, key, 'e');
            result_enc_trunc = result_enc & 0x000000000000fff;
            do {
            right_num = right_num ^ result_enc_trunc;
            }while(right_num>999);
        }
        printf("\n\nDecryption Round %d",(i+1));
        printf("\nLeft half = %d",left_num);
        printf("\nRight half = %d",right_num);
    }
    struct arrbin lbin = dectobin(left_num);
    struct arrbin rbin = dectobin(right_num);
    int dec_bin[20];
    for(i=0;i<10;i++){
        dec_bin[i] = rbin.binnum[i];
        dec_bin[i+10] = lbin.binnum[i];
    }
    int dec_hex=0;
    b=1;
    printf("\n\nDecrypted Tweak Number in Binary = ");
    for(i=19;i>=0;i--){
      printf("%d",dec_bin[i]);
    }
    for(i=0;i<20;i++){
      dec_hex = dec_hex + b*dec_bin[i];
      b*=2;
    }
    printf("\n\nDecrypted Tweak Number = %d",dec_hex);

    int dec_hex_arr[6],dec_data[6];
    int dec_hex1 = dec_hex;
    i=0;
    while (dec_hex1 != 0) {
        r = dec_hex1 % 10;
        dec_hex_arr[i] = r;
        i++;
        dec_hex1 = dec_hex1 / 10;
    }
    for(k=i;k<6;k++){
        dec_hex_arr[k] = 0;
    }
    printf("\n\nTweak = ");
    for (j=5;j>=0;j--) {

        printf("%d",tweak[j]);
    }
    for (j=0;j<6;j++) {
        dec_data[j] = dec_hex_arr[j] - tweak[j];
        if (dec_data[j]<0){
            dec_data[j] = 10 + dec_data[j];
        }
    }
    int dec_out[16];
    r=0;
    for (j = 15; j > 11; j--) {
            dec_out[r] = arr1[j];
            r++;
    }
    for (j = 0; j < 6; j++) {
            dec_out[r] = dec_data[j];
            r++;
    }
    for (j = 5; j >= 0; j--) {
            dec_out[r] = arr1[j];
            r++;
    }
    printf("\n\nDecrypted Output = ");
    for (j = 15; j >=0; j--) {
        printf("%d",dec_out[j]);
    }
}
int main()
{
    char str;
    printf("Enter the choice: E for Encryption and D for Decryption \n");
    scanf("%c",&str);
    if(str == 69 || str == 101){
        encrypt();
    }
    else if (str == 68 || str == 100) {
        decrypt();
    }
    else{
        printf("Invalid choice");
    }
    getch();
    return 0;

}
