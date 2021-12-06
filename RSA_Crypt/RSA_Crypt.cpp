#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <wincrypt.h>

using namespace std;

void save_keys(HCRYPTKEY& hExchangeKey, HCRYPTKEY& hExportKey);

void print(string text)
{
	cout << text;
}
void cw(string text)
{
	print(text);
	cout << endl;
}
void print_menu(int& operation)
{
	cw("0. Exit");
	cw("1. Gen All Keys");
	cw("2. Encrypt Data");
	cw("3. Decrypt Data");
	print("Your choice: ");
	cin >> operation;
}

void gen_all_keys(HCRYPTPROV& prov, HCRYPTKEY& hExchangeKey, HCRYPTKEY& hSessionKey, HCRYPTKEY& hExportKey)
{
	string pass = "";
	print("Enter password: ");
	cin >> pass;

	if (!CryptGenKey(prov, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &hExchangeKey))
		cw("ExchangeKey Gen Error");
	if (!CryptGenKey(prov, CALG_AES_256, CRYPT_EXPORTABLE, &hSessionKey))
		cw("SessionKey Gen Error");

	HCRYPTHASH hHash;
	if (!CryptCreateHash(prov, CALG_SHA_256, NULL, 0, &hHash))
	{
		cw("CryptCreateHash Error");
		return;
	}
	// Заполнение хеша паролем
	if (!CryptHashData(hHash, (BYTE*)pass.c_str(), pass.length(), 0))
	{
		cw("CryptHashData Error");
		return;
	}

	/// Метод аналогичен CryptGenKey за исключением того, что ключи будут сгенерированы не случайно, а опираясь на хеш
	// CALG_AES_256 - симмтричный алгоритм шифрования
	// CRYPT_EXPORTABLE - нужен для того, чтобы после мы могли прокинуть ключ в CryptExportKey
	if (!CryptDeriveKey(prov, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hExportKey))
		cw("CryptDeriveKey Error");

	CryptDestroyHash(hHash);
	cw("...Keys generation finished");
	cw("Saving keys...");
	save_keys(hExchangeKey, hExportKey);
}

void save_keys(HCRYPTKEY& hExchangeKey, HCRYPTKEY& hExportKey)
{
	{ // Записывает приватный ключ ExchangeKey шифрованный ExportKey благодаря методу CryptExportKey
		vector<char> vPrivateKey;
		DWORD dwLen = 0;
		if (!CryptExportKey(hExchangeKey, hExportKey, PRIVATEKEYBLOB, 0, NULL, &dwLen))
		{
			cw("PrivateKey-> ExportKey[1] Error");
			return;
		}
		vPrivateKey.resize(dwLen);
		if (!CryptExportKey(hExchangeKey, hExportKey, PRIVATEKEYBLOB, 0, (BYTE*)vPrivateKey.data(), &dwLen))
			cw("PrivateKey-> ExportKey[2] Error");
		vPrivateKey.resize(dwLen);
		ofstream out("private.key", ios::binary);
		out.write(vPrivateKey.data(), vPrivateKey.size());
	}

	{ // Записывает публичный ключ из ExchangeKey, шифруя его NULL в поле ExportKey в методе CryptExportKey
		vector<char> vPublicKey;
		DWORD dwLen = 0;
		if (!CryptExportKey(hExchangeKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwLen))
		{
			cw("PublicKey-> ExportKey[1] Error");
			return;
		}
		vPublicKey.resize(dwLen);
		if (!CryptExportKey(hExchangeKey, NULL, PUBLICKEYBLOB, 0, (BYTE*)vPublicKey.data(), &dwLen))
			cw("PublicKey-> ExportKey[2] Error");
		vPublicKey.resize(dwLen);
		ofstream out("public.key", ios::binary);
		out.write(vPublicKey.data(), vPublicKey.size());
	}

	cw("...Saving keys finished");
}


int main()
{
	// криптопровайдер
	HCRYPTPROV hProvider;
	HCRYPTKEY hExchangeKey, hSessionKey, hExportKey;

	// Получаем контекст
	if (!CryptAcquireContext(&hProvider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		cw("AcquireContext Error");
		return false;
	}

	while (true)
	{
		int operation = 0;
		print_menu(operation);
		switch (operation)
		{
			case 0:
			{
				cw("Exit...");
				return false;
			}
			case 1:
			{
				cw("Generating all keys...");
				gen_all_keys(hProvider, hExchangeKey, hSessionKey, hExportKey);
				break;
			}
			case 2:
			{
			}
		}
	}

	return false;
}