#include <stdio.h>
#include <stdint.h>
#include "contiki.h"

typedef uint64_t bit64;
bit64 constants[16] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};
bit64 state[5] = { 0 }, t[5] = { 0 };
   
bit64 rotate(bit64 x, int l) { 
   bit64 temp;
   temp = (x >> l) ^ (x << (64 - l)); 
   return temp;  
 }

void print_state(bit64 state[5]) {
    printf(" key[0] :%016llxx\n", state[1] );
    printf(" IV :%016llxx\n", state[0] );
    printf(" key[1] :%016llxx\n", state[2] );
    printf(" nonce[0] :%016llxx\n", state[3] );
    printf(" nonce[1] :%016llxx\n", state[4] );
}
void sbox(bit64 x[5]) {  
   x[0] ^=x[4]; x[4] ^=x[3]; x[2] ^= x[1];
   t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
   t[0] = ~t[0]; t[1] = ~t[1]; t[2]  = ~t[2]; t[3] =~t[3]; t[4] = ~t[4];
   t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
   x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= t[0];
   x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^=x[2]; x[2] = ~x[2]; 
 }

void linear(bit64 state[5]) { 
   bit64 temp0, temp1;
   temp0 = rotate(state[0],19);
   temp1 = rotate(state[0],28);
   state[0] ^= temp0 ^ temp1; 
   temp0 = rotate(state[1],61);
   temp1 = rotate(state[1],39);
   state[1] ^= temp0 ^ temp1;
   temp0 = rotate(state[2],1);
   temp1 = rotate(state[2],6);
   state[2] ^= temp0 ^ temp1;
   temp0 = rotate(state[3],10);
   temp1 = rotate(state[3],17);
   state[3] ^= temp0 ^ temp1;
   temp0 = rotate(state[4],7);
   temp1 = rotate(state[4],41);
   state[4] ^= temp0 ^ temp1;
 }

void add_constant(bit64 state[5], int i, int a) { 
   state[2] = state[2] ^ constants[12 - a + i]; 
}

void p(bit64 state[5], int a) {
   int i;
   for (i = 0; i < a; i++) { 
   add_constant(state, i, a);
   sbox(state);
   linear(state);
   }
 }
  
   void initialization(bit64 state[5], bit64 key[2]) {
   p(state, 12);
   state[3] ^= key[0];
   state[4] ^= key[1];
   
 }
   void encrypt(bit64 state[5], int lenght, bit64 plaintext[], bit64 ciphertext[]) { 
   ciphertext[0] = plaintext[0] ^ state[0];
   int i;
   for ( i = 1; i < lenght; i++){
   p(state, 6);
   ciphertext[i] = plaintext[i] ^ state[0];
   state[0] = plaintext[i]^state[0];
   }
}
   void finalization(bit64 state[5], bit64 key[2]){
   state[0] ^= key[0];
   state[1] ^= key[1];
   p(state, 12);
   }
   

/*---------------------------------------------------------------------------*/
PROCESS(ascon_process, "Ascon Code Process");
AUTOSTART_PROCESSES(&ascon_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ascon_process, ev, data)
{
    PROCESS_BEGIN();
    bit64 nonce[2] = { 0 };
    bit64 key[2] = { 0 };
    bit64 IV = 0x80400c8600000000;
    bit64 plaintext[] = { 0x123456789abcdef, 0x82187 }, ciphertext[10] = { 0 };
    state[0] = IV;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];
    initialization(state, key); 
    print_state(state);
    encrypt(state, 2, plaintext, ciphertext);
    printf("ciphertext: %016llxx %016llxx\n",ciphertext[0], ciphertext[1]);
    finalization(state, key);
    printf("tag: %016llxx %016llxx",state[3],state[4]);
    printf("Ascon Code Compiled\n");
    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
