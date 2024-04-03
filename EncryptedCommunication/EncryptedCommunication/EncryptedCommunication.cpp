#include <iostream>
#include <vector>
#include <random>
#include <math.h>
#include <iomanip>
#include "EncryptedCommunication.hpp"




/*-----Define-----*/
void Caesar_Test();
void OneTimePad_Test();
void SSC_Test();





int main() {
	std::bitset<5> d = 0b01101;
	std::cout << DES::CShiftR(d, 1).to_string();
}



//シーザー暗号の暗号化復号化テスト
void Caesar_Test() {
	std::cout << std::setfill('>') << std::setw(20) << "Caesar_Test" << std::endl;

	srand((unsigned int)time(NULL));

	//平文
	std::string PlainText = "HelloWorld!";
	//Key
	char        Key = rand() % 3;

	//暗号化
	std::string CipherText = Caesar::To_CipherText(PlainText, Key);
	std::cout << "暗号文:" << CipherText << std::endl;

	//復号化
	std::string ToPlainText = Caesar::To_PlainText(CipherText, Key);
	std::cout << "復号文:" << ToPlainText << std::endl;
}


//使い捨てパッド暗号の暗号化復号化テスト
void OneTimePad_Test() {
	std::cout << std::setfill('>') << std::setw(20) << "OneTimePad_Test" << std::endl;

	srand((unsigned int)time(NULL));

	//平文
	std::string       PlainText = "HelloWorld!";

	//keyの作成
	std::vector<char> Key = OneTimePad::Make_OneTimePad_Key(PlainText.size());

	//暗号化した文
	std::string       CipherText = OneTimePad::OneTimePad(PlainText, Key);
	std::cout << "暗号文:" << CipherText << std::endl;

	//復号化した文
	std::string       ToPlainText = OneTimePad::OneTimePad(CipherText, Key);
	std::cout << "復号文:" << ToPlainText << std::endl;
	
	return;
}


//単一換字暗号の暗号化復号化テスト
void SSC_Test() {
	std::cout << std::setfill('>') << std::setw(20) << "SSC_Test" << std::endl;

	//engine
	std::random_device rd;
	//ASCIIの20(SP)~7B({)の範囲の単一換字表を作成
	std::vector<std::pair<char, char>> dic = SSC::MakeDic<std::mt19937>(32, 'z', std::mt19937(rd()));

	std::string PlainText = "HelloWorld!";

	//暗号化
	std::string CipherText = SSC::SSC(PlainText, dic);
	std::cout << "暗号文:" << CipherText << std::endl;

	//復号化
	std::cout << "復号文:" << SSC::SSC(CipherText, dic) << std::endl;
}