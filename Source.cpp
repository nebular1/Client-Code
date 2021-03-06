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
#include <string>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

#define BUFSIZE 1024

unsigned char userKey[16] = "";
AES_KEY key;
#define DEFAULT_PORT "27015"
#define DEFAULT_ADDRESS "localhost"

void GenKeys(char secret[]) {

	/* óêàçàòåëü íà ñòðóêòóðó äëÿ õðàíåíèÿ êëþ÷åé */
	RSA * rsa = NULL;

	unsigned long bits = 128; /* äëèíà êëþ÷à â áèòàõ */

	/*ãåíåðàöèÿ êëþ÷à RSA*/
	FILE * privKey_file = NULL, *pubKey_file = NULL;
	/* êîíòåêñò àëãîðèòìà øèôðîâàíèÿ */
	const EVP_CIPHER *cipher = NULL;
	/*Ñîçäàåì ôàéëû êëþ÷åé*/
	privKey_file = fopen("\private.key", "wb");
	pubKey_file = fopen("\public.key", "wb");
	/* Ãåíåðèðóåì êëþ÷è */
	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	/* Ôîðìèðóåì êîíòåêñò àëãîðèòìà øèôðîâàíèÿ */
	cipher = EVP_get_cipherbyname("bf-ofb");
	/* Ïîëó÷àåì èç ñòðóêòóðû rsa îòêðûòûé è ñåêðåòíûé êëþ÷è è ñîõðàíÿåì â ôàéëàõ.
	* Ñåêðåòíûé êëþ÷ øèôðóåì ñ ïîìîùüþ ïàðîëüíîé ôðàçû*/
	PEM_write_RSAPrivateKey(privKey_file, rsa, cipher, NULL, 0, NULL, secret);
	PEM_write_RSAPublicKey(pubKey_file, rsa);
	/* Îñâîáîæäàåì ïàìÿòü, âûäåëåííóþ ïîä ñòðóêòóðó rsa */
	RSA_free(rsa);
	fclose(privKey_file);
	fclose(pubKey_file);
	printf("Êëþ÷è ñãåíåðèðîâàíû è ïîìåùåíû â ïàïêó VS2015\n");
}

void GenKeysMenu() {
	char secret[128] = "";
	system("cls");
	printf("Ââåäèòå ïàðîëüíóþ ôðàçó äëÿ çàêðûòîãî êëþ÷à: ");
	scanf(secret);
	GenKeys(secret);
}
void aes_encrypt()
{
	int outlen, inlen;
	FILE *in = fopen("in.txt", "rb"), *out = fopen("encrypt.txt", "wb"), *keyfile = fopen("aeskey.txt", "wb");
	unsigned char inbuffer[1024] = "";
	unsigned char encryptedbuffer[1024] = "";
	unsigned char outbuffer[1024] = "";

	/*ãåíåðàöèÿ êëþ÷à AES*/
	if (!RAND_bytes(userKey, 16))
		exit(-1);
	AES_set_encrypt_key(userKey, 128, &key);
	fwrite(userKey, 1, 16, keyfile);
	fclose(keyfile);

	/* Øèôðóåì ñîäåðæèìîå âõîäíîãî ôàéëà */
	while (1) {
		inlen = fread(inbuffer, 1, 16, in);
		if (inlen <= 0) break;
		AES_encrypt(inbuffer, encryptedbuffer, &key);
		fwrite(encryptedbuffer, 1, 16, out);
	}
	printf("Ñîäåðæèìîå ôàéëà in.txt áûëî çàøèôðîâàíî è ïîìåùåíî â ôàéë encrypt.txt\n");
	fclose(in);
	fclose(out);
}
void Encrypt() {
	/* ñòðóêòóðà äëÿ õðàíåíèÿ îòêðûòîãî êëþ÷à */
	RSA * pubKey = NULL;
	FILE * pubKey_file = NULL;
	unsigned char *ctext, *ptext;
	int inlen, outlen;
	/* Ñ÷èòûâàåì îòêðûòûé êëþ÷ */
	pubKey_file = fopen("\public.key", "rb");
	pubKey = PEM_read_RSAPublicKey(pubKey_file, NULL, NULL, NULL);
	fclose(pubKey_file);

	/* Îïðåäåëÿåì äëèíó êëþ÷à */
	int key_size = RSA_size(pubKey);
	ctext = (unsigned char *)malloc(key_size);
	ptext = (unsigned char *)malloc(key_size);
	OpenSSL_add_all_algorithms();

	int out = _open("sentrsa.file", O_CREAT | O_TRUNC | O_RDWR, 0600);
	int in = _open("aeskey.txt", O_RDWR);
	/* Øèôðóåì ñîäåðæèìîå âõîäíîãî ôàéëà */
	while (inlen = _read(in, ptext, key_size - 11)) {
		//inlen = _read(in, ptext, key_size - 11);
		//if (inlen <= 0) break;
		outlen = RSA_public_encrypt(inlen, ptext, ctext, pubKey, RSA_PKCS1_PADDING);
		_write(out, ctext, outlen);
	}

	char *buffer;
	std::ifstream fileBuffer("encrypt.txt", std::ios::in | std::ios::binary);
	std::ofstream outputBuffer("sentrsa.file", std::ios::app | std::ios::binary);
	fileBuffer.seekg(0, std::ios::end);
	int filelen = fileBuffer.tellg();
	fileBuffer.seekg(0, std::ios::beg);
	buffer = new char[filelen];
	fileBuffer.read(buffer, filelen);
	outputBuffer.write(buffer, filelen);
	outputBuffer.close();
	fileBuffer.close();

	printf("Ñîäåðæèìîå ôàéëà encrypt.txt áûëî çàøèôðîâàíî è ïîìåùåíî â ôàéë sentrsa.file\n");
}

int __cdecl main()
{
	setlocale(LC_ALL, "Russian");

	GenKeysMenu();
	aes_encrypt();
	Encrypt();

	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	char cli[10] = "localhost";
	char recvbuf[BUFSIZE];
	int iResult;
	int recvbuflen = BUFSIZE;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(DEFAULT_ADDRESS, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}
	char *buffer;
	std::ifstream fileBuffer("sentrsa.file", std::ios::in | std::ios::binary);
	fileBuffer.seekg(0, std::ios::end);
	int filelen = fileBuffer.tellg();
	fileBuffer.seekg(0, std::ios::beg);
	buffer = new char[filelen];
	fileBuffer.read(buffer, filelen);

		// Send an initial buffer
		iResult = send(ConnectSocket, buffer, filelen, 0);
		if (iResult == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}
		printf("Áàéò ïåðåäàíî: %ld\n", iResult);

	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();
	_getch();
	return 0;
}