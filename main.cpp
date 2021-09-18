#define     CONSOLE_DEBUG false      // Mostra no console o resultado ao inves de mandar para um arquivo
#define SAMPLE_TEXT_DEBUG false      // Passa um texto pequeno para teste (SAMPLE TEXT)

// PARA ESCOLHER O NUMERO DE RODADAS, CONSULTAR utils.h

#include <iostream>
#include <stdint.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#include "Utils.h"
#include "AES.h" 

int main( int argc, char* argv[] ){

    std::cout << '\n' << " --|Cifrador e Decifrador AES de PPMs|--";
    std::cout << '\n' << " ---------------------------------------" << "\n\n";
    std::string _cin;
    
    if( !SAMPLE_TEXT_DEBUG ) {

        std::cout << " Entre com o nome do arquivo (sem a extensao): ";
        std::cin >> _cin;
        _cin += ".ppm";

    }

    //Lendo a imagem
    std::ifstream fin(_cin);

    //Erro ao abrir a imagem
    if( !SAMPLE_TEXT_DEBUG && !fin ) {

        std::cerr << " \nArquivo nao encontrado...\n\n" << std::endl;
        std::cin.ignore();
        return -1;

    }

    std::cout << "\n";

    std::cout << " No momento, cifrando com " << N_ROUNDS 
              << " rodadas. ( Para alterar, acesse utils.h ) \n\n";

    // Lendo o conteudo da imagem
    std::string message = "";
    std::string temp = "";

    // Lendo o cabecalho da imagem
    std::string ppmType = "";
    std::string lenght, height, RGBRange = "";

    if( !SAMPLE_TEXT_DEBUG ) {
        
        fin >> ppmType >> lenght >> height >> RGBRange;

        while( std::getline( fin, temp ) )
            message += temp;

    }

    else {

        message = "SAMPLE TEXT";

    }

    uint8_t expandedKey[176] = { 0 };

    // Fazendo padding na mensagem caso não tenha 16 bytes
    int32_t originalLen = message.length();
    int32_t lenOfPaddedMessage = originalLen;

    // Arredondando para o multiplo de 16 mais proximo
    if( lenOfPaddedMessage % 16 != 0 )
        lenOfPaddedMessage = (lenOfPaddedMessage / 16 + 1) * 16;

    uint8_t* paddedMessage = new uint8_t[lenOfPaddedMessage];

    for( int32_t i = 0; i < lenOfPaddedMessage; i++ ) {

        if( i >= originalLen )
            paddedMessage[i] = 0;

        else
            paddedMessage[i] = message[i];

    }

    // Expandindo a chave para o tamanho da mensagem
    KeyExpansion( key, expandedKey );

    for( int32_t i = 0; i < lenOfPaddedMessage; i += 16 )
        AESEncriptar( paddedMessage + i, expandedKey );

    // Criando o arquivo de saida
    std::ofstream fout("encrypt.ppm");

    if( !SAMPLE_TEXT_DEBUG ) {
        
        // Cabecalho do arquivo
        fout << ppmType  << '\n';
        fout << lenght   << " " << height << '\n';
        fout << RGBRange << '\n';

    }

    float progress = 0.0f;

     if( CONSOLE_DEBUG ) {

        std::cout << "\n Cifra :\n" << '\n';
        std::cout << " ";
     }

    for( int32_t i = 0; i < lenOfPaddedMessage; i++ ){

        if( !CONSOLE_DEBUG ) {

            // Criando o hash
            if( paddedMessage[i] / 16 < 10 )  fout << (char)(( paddedMessage[i] / 16 ) + '0');
            if( paddedMessage[i] / 16 >= 10 ) fout << (char)(( paddedMessage[i] / 16 - 10) + 'A');
            
            if( paddedMessage[i] % 16 < 10 )  fout << (char)(( paddedMessage[i] % 16 ) + '0');
            if( paddedMessage[i] % 16 >= 10 ) fout << (char)(( paddedMessage[i] % 16 - 10) + 'A');
            
            fout << " " ;
    
        }

        else {

            PrintHex( paddedMessage[i] );
            std::cout << " ";

            // Precisamos salvar o resultado de qualquer maneira
            if( paddedMessage[i] / 16 < 10 )  fout << (char)(( paddedMessage[i] / 16 ) + '0');
            if( paddedMessage[i] / 16 >= 10 ) fout << (char)(( paddedMessage[i] / 16 - 10) + 'A');
            
            if( paddedMessage[i] % 16 < 10 )  fout << (char)(( paddedMessage[i] % 16 ) + '0');
            if( paddedMessage[i] % 16 >= 10 ) fout << (char)(( paddedMessage[i] % 16 - 10) + 'A');
            fout << " " ;
    
        }

        progress = (float)((i + 1) * 100 / lenOfPaddedMessage) + 1; 

        // Espaco para o arquivo nao ficar em uma so linha
        if( i > 0 && i % 15 == 0 && !CONSOLE_DEBUG) {
            fout << '\n';
        }        
        
        // Progresso da cifracao
        if( i % 65536 == 0 && !CONSOLE_DEBUG ) {
            std::cout << "\r Criptografando... " << std::fixed << std::setprecision(1) << progress << '%' << std::flush;
        }

    }

    delete[] paddedMessage;

    std::cout << "\n\n\n Arquivo criptografado com sucesso. \n\n";
    std::cout << " Lendo o arquivo criptografado para decifrar...\n";

    // Lendo o arquivo com cifra e preparando as variaveis
    std::ifstream enc_fin("encrypt.ppm");
    std::string cypher = "";
    ppmType = "";
    lenght, height, RGBRange = "";
    temp = "";
    expandedKey[176] = { 0 };

    if( !SAMPLE_TEXT_DEBUG ) {
        
        // Lendo o cabecalho da imagem
        enc_fin >> ppmType >> lenght >> height >> RGBRange;

    }

    progress = 0.0f;

    uint8_t currentCypher[] = { 0 };

    // Lendo o arquivo em chunck para não expludir a memória
    std::ofstream dec_fout("dec.ppm");

    if( !SAMPLE_TEXT_DEBUG ) {

        // Cabecalho do arquivo
        dec_fout << ppmType << '\n';
        dec_fout << lenght << " " << height << '\n';
        dec_fout << RGBRange << '\n';

    }

    std::vector<char> buffer (1024, 0);

    while( !enc_fin.eof() ) {

        enc_fin.read( buffer.data(), buffer.size() );
        std::streamsize s = fin.gcount();

        // Fazendo padding na mensagem caso não tenha 16 bytes
        originalLen = 16;
        lenOfPaddedMessage = originalLen;

        // Arredondando para o multiplo de 16 mais proximo
        if( lenOfPaddedMessage % 16 )
            lenOfPaddedMessage = (originalLen / 16 + 1) * 16;

        paddedMessage = new uint8_t[lenOfPaddedMessage];

        for( int32_t i = 0; i < lenOfPaddedMessage; i++ ) {

            if( i >= originalLen )
                paddedMessage[i] = 0;

            else
                paddedMessage[i] = message[i];

        }

        // Expandindo a chave para o tamanho da mensagem
        KeyExpansion( key, expandedKey );

        for( uint32_t i = 0; i < lenOfPaddedMessage; i += 16 )
            AESDecifrar( paddedMessage + i, expandedKey );

        for( uint32_t i = 0; i < lenOfPaddedMessage; i++ ) {

            if( !CONSOLE_DEBUG ) {

                // Criando o hash
                if( paddedMessage[i] / 16 < 10 )  dec_fout << (char)(( paddedMessage[i] / 16 ) + '0');
                if( paddedMessage[i] / 16 >= 10 ) dec_fout << (char)(( paddedMessage[i] / 16 - 10) + 'A');
                
                if( paddedMessage[i] % 16 < 10 )  dec_fout << (char)(( paddedMessage[i] % 16 ) + '0');
                if( paddedMessage[i] % 16 >= 10 ) dec_fout << (char)(( paddedMessage[i] % 16 - 10) + 'A');
                
                dec_fout << " " ;

            }

            else {

                PrintHex( paddedMessage[i] );
                std::cout << " ";

            } 

            //Espaco para o arquivo nao ficar em uma so linha
            if( i % 16 == 0 && !CONSOLE_DEBUG) {
                dec_fout << '\n';
            }        
            

        }

        delete[] paddedMessage;
    }

    std::cout << "\n\n Arquivo descifrado com sucesso. \n\n";
    std::cout << " Checar os arquivos encrypt.ppm e dec.ppm. \n\n\n\n";

    // Segura o console, caso seja necessario
    std::cin.ignore();


    return 0;

}
