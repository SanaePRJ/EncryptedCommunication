#ifndef SANAE_ENCRYPTEDCOMMUNICATION_HPP
#define SANAE_ENCRYPTEDCOMMUNICATION_HPP


#include <string>
#include <time.h>
#include <vector>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <random>
#include <algorithm>




namespace Caesar 
{
	//Caesar暗号
	std::string To_CipherText(const std::string&, char); //暗号化
	std::string To_PlainText(const std::string&, char);  //復号化
}

namespace OneTimePad
{
	//使い捨てパッド暗号
	std::string OneTimePad(const std::string&, std::vector<char>);  //変換

	//keyを作成する
	std::vector<char> Make_OneTimePad_Key(size_t, std::function<char(void)>);
}

namespace SSC {
	//単一換字暗号
	std::string SSC(const std::string&, std::vector<std::pair<char, char>>);  //変換

	//単一換字表を作成(範囲指定)
	template<typename Engine>
	std::vector<std::pair<char, char>> MakeDic(char, char, Engine);
}



/*----------Caesar暗号----------*/
namespace Caesar {
	//暗号化
	std::string To_CipherText(const std::string& PlainText,char Key)
	{
		//格納先の定義
		std::string buf(PlainText.size(), 0);

		//すべての要素に対して+Keyする。
		for (size_t i = 0; i < PlainText.size(); i++)
			buf[i] = PlainText[i] + Key;

		return buf;
	}
	//復号
	std::string To_PlainText(const std::string& CipherText, char Key)
	{
		//格納先の定義
		std::string buf(CipherText.size(), 0);

		//すべての要素に対して-Keyする。
		for (size_t i = 0; i < CipherText.size(); i++)
			buf[i] = CipherText[i] - Key;

		return buf;
	}
}




/*----------使い捨てパッド暗号----------*/
namespace OneTimePad {
	std::string OneTimePad(const std::string& text, std::vector<char> key)
	{
		//平文,暗号文がkeyサイズと違う場合
		if (text.size() != key.size())
			throw std::invalid_argument("different size.");

		//格納先の定義
		std::string buf(text.size(), 0);

		//すべての要素に対してxorする。
		for (size_t i = 0; i < text.size(); i++)
			buf[i] = text[i] ^ key[i];

		return buf;
	}

	//keyの生成
	std::vector<char> Make_OneTimePad_Key(size_t size, std::function<char(void)> func = []() {return static_cast<char>(rand() % 255); })
	{
		//サイズ分生成(0で初期化)
		std::vector<char> key(size, 0);

		//生成
		for (size_t pos = 0; pos < size; pos++)
			key[pos] = func();

		return key;
	}
}




/*----------単一換字暗号----------*/
namespace SSC {
	std::string SSC(const std::string& Text,std::vector<std::pair<char,char>> Dic) {
		//テキストサイズ分
		std::string buf(Text.size(),0);

		//各文字を変換
		for (size_t i = 0; i < Text.size(); i++) {
			//first又はsecondで探す
			auto Search = std::find_if(Dic.begin(), Dic.end(), [&Text, &i](std::pair<char, char> ele) {return ele.first == Text[i] || ele.second == Text[i]; });

			//見つからない場合
			if (Search == Dic.end())
				throw std::invalid_argument("Not Found.");

			//firstで見つかった場合second
			if ((*Search).first == Text[i])
				buf[i] = (*Search).second;
			//secondで見つかった場合firstにする
			else
				buf[i] = (*Search).first;
		}

		return buf;
	}

	//単一換字表を作成する。(引数として範囲を入れる。例:A~z)
	template<typename Engine = std::mt19937>
	std::vector<std::pair<char, char>> MakeDic(char first, char last, Engine engine)
	{
		//firstの方が大きい場合入れ替え
		if (last < first)
			std::swap(last,first);

		//first~lastなのでlast-firstの時に+1する。
		const auto range = [&first,&last]()->size_t {return static_cast<size_t>(last - first) + 1; };

		//奇数個の時できないので範囲を増加
		if (range() & 1)
			last++;

		//first~lastまで数値を入れる
		std::vector<char> buf(range());
		for (size_t i = 0; i < range(); i++)
			buf[i] = first + i;

		//シャッフルする。
		std::shuffle(buf.begin(),buf.end(),engine);

		//半数にする
		const size_t halfsize = range() / 2;

		//対応させるのでサイズは半分でいい
		std::vector<std::pair<char, char>> ret(halfsize);
		for (size_t i = 0; i < halfsize;i++)
			ret[i] = std::pair<char, char>{buf[i],buf[halfsize+i]};

		return ret;
	}
}




#endif