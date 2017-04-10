// Crypto_7.cpp: главный файл проекта.

#include "stdafx.h"
#include <iostream>
#include <cmath>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>


using namespace System;
using namespace std;

enum Mode
{
	ENCRYPT,
	DECRYPT
};

int S[8][16] =
{
	{ 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
	{ 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
	{ 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
	{ 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
	{ 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
	{ 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
	{ 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
	{ 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 },
};

int subKeyInd[] = { 0, 1, 2, 3, 4, 5, 6, 7,
					0, 1, 2, 3, 4, 5, 6, 7,
					0, 1, 2, 3, 4, 5, 6, 7,
					7, 6, 5, 4, 3, 2, 1, 0 };

int getBit(unsigned __int32 n, int i)
{
	return (n >> i) & 1;
}

int getBit(__int64 n, int i)
{
	return (n >> i) & 1;
}

int getBit( char n, int i)
{
	return (n >> i) & 1;
}

__int64 toInt64(Byte *buff)
{
	__int64 block = 0;
	block |= buff[0]; block <<= 8;
	block |= buff[1]; block <<= 8;
	block |= buff[2]; block <<= 8;
	block |= buff[3]; block <<= 8;
	block |= buff[4]; block <<= 8;
	block |= buff[5]; block <<= 8;
	block |= buff[6]; block <<= 8;
	block |= buff[7];
	return block;
}

unsigned __int32 toInt32(Byte *buff)
{
	unsigned __int32 block = 0;
	block |= buff[0]; block <<= 8;
	block |= buff[1]; block <<= 8;
	block |= buff[2]; block <<= 8;
	block |= buff[3];
	return block;
}

char getByteByIndex(__int64 num, int i)
{
	return num >> (56 - i * 8) & 255;
}

//Возвращает i байт в числе num
char getByteByIndex(unsigned __int32 num, int i)
{
	return (num >> (24 - i * 8)) & 255;
}

//Выполняет подстановки по таблице S
unsigned __int32 sBlocks(unsigned __int32 word)
{
	Byte newWord[4] = {};

	for (int i = 0; i < 4; i++)
	{
		Byte byte = getByteByIndex(word, i);
		int lByte = (byte >> 4) & 15;
		int rByte = byte & 15;
		newWord[i]= (S[i * 2][lByte] << 4) | S[i * 2 + 1][rByte];
	}
	return toInt32(newWord);
}

void prepareForWrite(char *buff, __int64 num)
{
	for (int i = 0; i < 8; i++)
		buff[i] = getByteByIndex(num, i);
}
//Подготовка буфера для записи в файл
void prepareForWrite(char *buff, unsigned __int32 num)
{
	for (int i = 0; i < 4; i++)
		buff[i] = getByteByIndex(num, i);
}

//Циклический сдвиг влево на 11 бит
unsigned __int32 cicle(unsigned __int32 num)
{
	for (int i = 0; i < 11; i++)
	{
		int p = getBit(num, 31);
		num <<= 1;
		num |= p;
	}
	return num;
}

//Реализует 32 цикла шифрования/расшифрования по алгоритму ГОСТ 28147-89
void cryptEngine(unsigned __int32 left, unsigned __int32 right, unsigned __int32* Key, unsigned __int32 &resLeft, unsigned __int32 &resRight, Mode mode)
{
	for (int i = 0; i < 32; i++)
	{
		int ind = 0;
		if (mode == Mode::DECRYPT)
			ind = 31 - i;
		else
			ind = i;
		unsigned __int32 res = sBlocks((right + Key[subKeyInd[ind]]) % 4294967296);
		res = cicle(res);
		unsigned __int32 temp = right;
		right = res ^ left;
		left = temp;
	}
	resLeft = left;
	resRight = right;
}

//Функция чтения из файла, шифрации/дешифрации и записи.
void GOST(char* source, unsigned __int32* Key, Mode mode)
{
	char* dest;
	switch (mode)
	{
	case Mode::ENCRYPT:
		dest = "code";
		break;
	case Mode::DECRYPT:
		dest = "result.jpg";
		break;
	default:
		break;
	}

	ifstream f(source, ios_base::binary);
	ofstream w(dest, ios_base::binary);
	while (!f.eof())
	{
		char bufferLeft[4] = {};
		f.read(bufferLeft, 4);
		unsigned __int32 left = toInt32((Byte*)bufferLeft);
		if (!f.eof())
		{
			char bufferRight[4] = {};
			f.read(bufferRight, 4);
			unsigned __int32 right = toInt32((Byte*)bufferRight);
			unsigned __int32 lRes = 0, rRes = 0;
			cryptEngine(left, right, Key, lRes, rRes, mode);
			memset(bufferLeft, 0, 4);
			memset(bufferRight, 0, 4);
			prepareForWrite(bufferLeft, lRes);
			prepareForWrite(bufferRight, rRes);
			//Записываем в файл в обратном порядке, для более удобной дешифрации
			w.write(bufferRight, 4); 
			w.write(bufferLeft, 4);
		}
		else
		{
			w.write(bufferLeft, 4);
		}
	}
	f.close();
	w.close();
}

void generateKey()
{
	ofstream f("key", ios_base::binary);
	for (int i = 0; i < 8; i++)
	{
		char buff[4] = {};
		unsigned __int32 part = rand();
		prepareForWrite(buff, part);
		f.write(buff, 4);
	}
	f.close();
}

void readKey(unsigned __int32* Key)
{
	ifstream f("key", ios_base::binary);
	for (int i = 0; i < 8; i++)
	{
		char buff[4] = {};
		f.read(buff, 4);
		Key[i] = toInt32((Byte* )buff);
	}
	f.close();
}

int main(array<System::String ^> ^args)
{
	unsigned __int32 Key[8] = {};
	//Считываем ключ заранее сгенерированный функцией generateKey
	readKey(Key);
	GOST("1.JPG", Key, Mode::ENCRYPT);
	GOST("code", Key, Mode::DECRYPT);
	system("pause");
    return 0;
}
