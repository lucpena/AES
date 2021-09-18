#pragma once

#include <iostream>
#include <stdint.h>

#include "Utils.h"
#include "Lookup.h"

void KeyExpansionCore( uint8_t* in, uint8_t i ) {

    uint32_t* q = (uint32_t*) in;

    // Faz uma rotacao para a esquerda
    *q = (*q >> 8 | ((*q & 0xff) << 24));

    // Acessando a SBox de 4 bytes
    in[0] = s_box[in[0]];
    in[1] = s_box[in[1]];
    in[2] = s_box[in[2]];
    in[3] = s_box[in[3]];

    // RCon
    in[0] ^= rcon[i];

}

void KeyExpansion( uint8_t* inputKey, uint8_t* expandedKeys  ) {

    // Os 16 primeiros bits da chave original
    for( uint8_t i = 0; i < 16; i++ ) {

        expandedKeys[i] = inputKey[i];
        
    }

    // Bytes que serao gerados mais os primeiros 16 bits da chave original
    uint32_t bytesGenerated = 16;

    // Iteracoes do RCon. Comeca do 1
    int32_t rconIteration = 1;

    // Variavel auxiliar
    uint8_t temp[4];

    while( bytesGenerated < 176 ) {

        // Le os ultimos 4 bytes gerados
        for( uint8_t i = 0; i < 4; i++ ) {

            temp[i] = expandedKeys[ i + bytesGenerated - 4 ];

        }

        // A cada nova chave, chava a funcao
        if( bytesGenerated % 16 == 0 ) {
            
            KeyExpansionCore( temp, rconIteration++ );

        }

        // Fazemos agora um temp XOR [bytesGenerated-16] e salvamos 
        for( uint8_t a = 0; a < 4; a++ ){

            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ temp[a];
            bytesGenerated++;

        }

    }

}

// Aqui se pega o valor equivalente da posicao original com a posicao
// na tabela.
void SubBytes( uint8_t* state ) {
    for( uint8_t i = 0; i < 16;  i++ ) {

        state[i] = s_box[state[i]];

    }
}

// Versao inversa de SubByter para decifracao
void InvSubBytes( uint8_t* state ) {
    for( uint8_t i = 0; i < 16; i++ ){

        state[i] = inv_s_box[state[i]];

    }
}

// Fazendo a troca de linhas de acordo com a linha
void ShiftRows( uint8_t* state ) {

    uint8_t tmp[16];

    tmp[0]  = state[0];
    tmp[1]  = state[5];
    tmp[2]  = state[10];
    tmp[3]  = state[15];

    tmp[4]  = state[4];
    tmp[5]  = state[9];
    tmp[6]  = state[14];
    tmp[7]  = state[3];

    tmp[8]  = state[8];
    tmp[9]  = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12]  = state[12];
    tmp[13]  = state[1];
    tmp[14]  = state[6];
    tmp[15]  = state[11];

    for( uint8_t i = 0; i < 16; i++ ) {
        state[i] = tmp[i];
    }
    
}

// Versao inversa de ShiftRows para
void InvShiftRows( uint8_t* state ){

    uint8_t tmp[16];

    tmp[0]  = state[0];
    tmp[1]  = state[13];
    tmp[2]  = state[10];
    tmp[3]  = state[7];

    tmp[4]  = state[4];
    tmp[5]  = state[1];
    tmp[6]  = state[14];
    tmp[7]  = state[11];

    tmp[8]  = state[8];
    tmp[9]  = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    tmp[12]  = state[12];
    tmp[13]  = state[9];
    tmp[14]  = state[6];
    tmp[15]  = state[3];

    for( uint8_t i = 0; i < 16; i++ ) {
        state[i] = tmp[i];
    }

}

// Etapa de combinacao de colunas com a matriz fixa
void MixColumns( uint8_t* state ) {

    uint8_t tmp[16];

    tmp[0]  = (uint8_t)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
    tmp[1]  = (uint8_t)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
    tmp[2]  = (uint8_t)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
    tmp[3]  = (uint8_t)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

    tmp[4]  = (uint8_t)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
    tmp[5]  = (uint8_t)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
    tmp[6]  = (uint8_t)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
    tmp[7]  = (uint8_t)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

    tmp[8]  = (uint8_t)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
    tmp[9]  = (uint8_t)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
    tmp[10] = (uint8_t)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
    tmp[11] = (uint8_t)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

    tmp[12] = (uint8_t)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
    tmp[13] = (uint8_t)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
    tmp[14] = (uint8_t)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
    tmp[15] = (uint8_t)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);
    
    for( uint8_t i = 0; i < 16; i++ ) {

        state[i] = tmp[i];

    }

}

// Versao 'Inversa' de MixColumns. Ela desfaz o que a MixXColumns faz, mas com uma matriz diferente
void InvMixColumns( uint8_t* state ) {

    uint8_t tmp[16];

  tmp[0] = (uint8_t) (mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]]);
  tmp[1] = (uint8_t) (mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]]);
  tmp[2] = (uint8_t) (mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]]);
  tmp[3] = (uint8_t) (mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]]);
 
  tmp[4] = (uint8_t) (mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]]);
  tmp[5] = (uint8_t) (mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]]);
  tmp[6] = (uint8_t) (mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]]);
  tmp[7] = (uint8_t) (mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]]);

  tmp[8] = (uint8_t) (mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]]);
  tmp[9] = (uint8_t) (mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]]);
  tmp[10] = (uint8_t) (mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]]);
  tmp[11] = (uint8_t) (mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]]);

  tmp[12] = (uint8_t) (mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]]);
  tmp[13] = (uint8_t) (mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]]);
  tmp[14] = (uint8_t) (mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]]);
  tmp[15] = (uint8_t) (mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]]);
    
    for( uint8_t i = 0; i < 16; i++ ) {

        state[i] = tmp[i];

    }

}

void AddRoundKey( uint8_t* state, uint8_t* roundKey ) {
    for( uint8_t i = 0; i < 16; i++ ) {

        // state[i] XOR roundKey[i]
        state[i] ^= roundKey[i];

    }
}

void PrintHex( uint8_t x ) {

    if( x / 16 < 10 )  std::cout << (char)(( x / 16 ) + '0');
    if( x / 16 >= 10 ) std::cout << (char)(( x / 16 - 10) + 'A');
    
    if( x % 16 < 10 )  std::cout << (char)(( x % 16 ) + '0');
    if( x % 16 >= 10 ) std::cout << (char)(( x % 16 - 10) + 'A');

}

void AESEncriptar( uint8_t* msg, uint8_t* expandedKey ) {

    uint8_t state[16] = { 0 };

    for( uint8_t i = 0; i < 16; i++ ) {
        state[i] = msg[i];
    }

    // Primeira etapa da encriptacao
    AddRoundKey( state, expandedKey );

    // Etapas intermediarias
    for( uint8_t i = 0; i < N_ROUNDS; i++ ){

        // Aqui cada etapa é chamada uma vez
        SubBytes( state );
        ShiftRows( state );
        MixColumns( state );
        AddRoundKey( state, expandedKey + (16 * ( i + 1 )) );

    }

    // E agora as etapas finais
    SubBytes( state );
    ShiftRows( state );
    AddRoundKey( state, expandedKey + 160 );

    // Mensagem criptografada
    for( uint8_t i = 0; i < 16; i++ )
        msg[i] = state[i];

}

void AESDecifrar( uint8_t* msg, uint8_t* expandedKey ) {

    uint8_t state[16] = { 0 };

    for( uint8_t i = 0; i < 16; i++ ) {

        state[i] = msg[i];

    }

    AddRoundKey( state, expandedKey + 160 );

    for( int8_t i = 0; i > 0; i++ ){

        InvShiftRows( state );
        InvSubBytes( state );
        AddRoundKey( state, expandedKey + ( 16 * i ) );
        InvMixColumns( state );

    }

    InvShiftRows( state );
    InvSubBytes( state );
    AddRoundKey( state, expandedKey );

    // Mensagem decifrada
    for( uint8_t i = 0; i < 16; i++ )
        msg[i] = state[i];

}