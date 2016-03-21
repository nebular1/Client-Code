#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <fstream>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

#define BUFSIZE 1024
#define KEYSIZE 16
#define SECRETSIZE 128
#define KEYBITS 128

unsigned char userKey[KEYSIZE] = "";
AES_KEY key;
#define DEFAULT_PORT "27015"
#define DEFAULT_ADDRESS "localhost"

void GenKeys(char secret[]) {
	RSA * rsa = NULL; /* pointer to the key structure */

	unsigned long bits = KEYBITS; /* key lenght in bits */

	FILE * privKey_file = NULL, *pubKey_file = NULL; 	/*RSA key generation*/
	
	const EVP_CIPHER *cipher = NULL; /* context of cypher algorithm */
	
	privKey_file = fopen("\private.key", "wb"); /*creating key files*/
	pubKey_file = fopen("\public.key", "wb");

	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL); 	/* generating keys */
	
	cipher = EVP_get_cipherbyname("bf-ofb"); /* forming context of cypher algorithm */
	/* receiving open and secret keys from rsa structure and saving them in files
	* cyphering the secret key with password phrase*/
	PEM_write_RSAPrivateKey(privKey_file, rsa, cipher, NULL, 0, NULL, secret);
	PEM_write_RSAPublicKey(pubKey_file, rsa);
	/* mem free */
	RSA_free(rsa);
	fclose(privKey_file);
	fclose(pubKey_file);
	printf("Keys were generated\n");
}

void GenKeysMenu() {
	char secret[SECRETSIZE] = "";
	system("cls");
	printf("Enter your password phrase: ");
	scanf(secret);
	GenKeys(secret);
}

void aes_encrypt()
{
	int inlen;
	FILE *in = fopen("in.txt", "rb"), *out = fopen("encrypt.txt", "wb"), *keyfile = fopen("aeskey.txt", "wb");
	unsigned char inbuffer[BUFSIZE] = "";
	unsigned char encryptedbuffer[BUFSIZE] = "";
	unsigned char outbuffer[BUFSIZE] = "";
	/*generating AES key*/
	if (!RAND_bytes(userKey, KEYSIZE))
		exit(-1);
	AES_set_encrypt_key(userKey, KEYBITS, &key);
	fwrite(userKey, 1, KEYSIZE, keyfile);
	fclose(keyfile);
	/* cyphering the input file */
	while (1) {
		inlen = fread(inbuffer, 1, KEYSIZE, in);
		if (inlen <= 0) break;
		AES_encrypt(inbuffer, encryptedbuffer, &key);
		fwrite(encryptedbuffer, 1, KEYSIZE, out);
	}
	printf("File in.txt was cyphered into encrypt.txt file\n");
	fclose(in);
	fclose(out);
}

int filelength(char inputname[])
{
	std::ifstream fileBuffer(inputname, std::ios::in | std::ios::binary); //open file for reading
	fileBuffer.seekg(0, std::ios::end);
	int result = fileBuffer.tellg(); //file size
	fileBuffer.close();

	return result;
}

char * binaryread(char inputname[], char outputname[], int len)
{
	char *buffer;
	int filelen;

	if (len == 0)
		filelen = filelength(inputname); //file size
	else
		filelen = len;

	std::ifstream fileBuffer(inputname, std::ios::in | std::ios::binary); //open file for reading

	fileBuffer.seekg(0, std::ios::beg);
	buffer = new char[filelen];
	fileBuffer.read(buffer, filelen); //reading file
	fileBuffer.close();
	if (outputname == 0)
		return buffer;
	else
	{
		std::ofstream outputBuffer(outputname, std::ios::app | std::ios::binary); //open file for writing
		outputBuffer.write(buffer, filelen); //writing to file
		outputBuffer.close();
	}
}

void Encrypt() {
	/* structure for the open key */
	RSA * pubKey = NULL;
	FILE * pubKey_file = NULL;
	unsigned char *ctext, *ptext;
	int inlen, outlen;
	/* reading open key */
	pubKey_file = fopen("\public.key", "rb");
	pubKey = PEM_read_RSAPublicKey(pubKey_file, NULL, NULL, NULL);
	fclose(pubKey_file);

	/* key size */
	int key_size = RSA_size(pubKey);
	ctext = (unsigned char *)malloc(key_size);
	ptext = (unsigned char *)malloc(key_size);
	OpenSSL_add_all_algorithms();

	int out = _open("sentrsa.file", O_CREAT | O_TRUNC | O_RDWR, 0600);
	int in = _open("aeskey.txt", O_RDWR);
	/* cyphering input file */
	while (inlen = _read(in, ptext, key_size - 11)) {
		outlen = RSA_public_encrypt(inlen, ptext, ctext, pubKey, RSA_PKCS1_PADDING);
		_write(out, ctext, outlen);
	}

	binaryread("encrypt.txt", "sentrsa.file", 0);

	printf("File encrypt.txt was cyphered into sentrsa.file file\n");
}

int Send_Buf(SOCKET sock, char *buf, int filelen) //sending buffer info through socket
{
	int iResult = send(sock, buf, filelen, 0); 
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
	printf("Bytes sent: %ld\n", iResult);
}

int Connect_Shutdown(SOCKET sock) //socket connection shutdown
{
	int iResult = shutdown(sock, SD_SEND); 
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
}

int Check_Socket(SOCKET sock) //socket check
{
	if(sock == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}
}

int __cdecl main()
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL, *ptr = NULL, hints; //structures for socket
	int iResult;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData); // Initialize Winsock
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints)); //initializing hints
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(DEFAULT_ADDRESS, DEFAULT_PORT, &hints, &result); // Resolve the server address and port
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	} 
	
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) { // Attempt to connect to an address until one succeeds

		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol); // Create a SOCKET for connecting to server
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}
		
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen); // Connect to server
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	Check_Socket(ConnectSocket);
	
	setlocale(LC_ALL, "Russian");
	GenKeysMenu(); //keys generation
	aes_encrypt(); //AES cyphering
	Encrypt(); //RSA cyphering

	char *pChar = binaryread("sentrsa.file", 0, 0); //reading from a file to buffer
	int filelen = filelength("sentrsa.file"); //file size for sending

	Send_Buf(ConnectSocket, pChar, filelen); //sending info
	Connect_Shutdown(ConnectSocket); // connection shutdown
	
	closesocket(ConnectSocket); // cleanup
	WSACleanup();
	_getch();
	return 0;
}
