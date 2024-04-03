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
#include <bitset>




template<size_t Count>
uint64_t pow(uint64_t arg) {
	return arg * pow<Count - 1>(arg);
}
template<>
uint64_t pow<0>(uint64_t arg) {
	return 1;
}


namespace Caesar 
{
	//Caesar�Í�
	std::string To_CipherText(const std::string&, char); //�Í���
	std::string To_PlainText(const std::string&, char);  //������
}

namespace OneTimePad
{
	//�g���̂ăp�b�h�Í�
	std::string OneTimePad(const std::string&, std::vector<char>);  //�ϊ�

	//key���쐬����
	std::vector<char> Make_OneTimePad_Key(size_t, std::function<char(void)>);
}

namespace SSC {
	//�P�ꊷ���Í�
	std::string SSC(const std::string&, std::vector<std::pair<char, char>>);  //�ϊ�

	//�P�ꊷ���\���쐬(�͈͎w��)
	template<typename Engine>
	std::vector<std::pair<char, char>> MakeDic(char, char, Engine);
}



/*----------Caesar�Í�----------*/
namespace Caesar {
	//�Í���
	std::string To_CipherText(const std::string& PlainText,char Key)
	{
		//�i�[��̒�`
		std::string buf(PlainText.size(), 0);

		//���ׂĂ̗v�f�ɑ΂���+Key����B
		for (size_t i = 0; i < PlainText.size(); i++)
			buf[i] = PlainText[i] + Key;

		return buf;
	}
	//����
	std::string To_PlainText(const std::string& CipherText, char Key)
	{
		//�i�[��̒�`
		std::string buf(CipherText.size(), 0);

		//���ׂĂ̗v�f�ɑ΂���-Key����B
		for (size_t i = 0; i < CipherText.size(); i++)
			buf[i] = CipherText[i] - Key;

		return buf;
	}
}




/*----------�g���̂ăp�b�h�Í�----------*/
namespace OneTimePad {
	std::string OneTimePad(const std::string& text, std::vector<char> key)
	{
		//����,�Í�����key�T�C�Y�ƈႤ�ꍇ
		if (text.size() != key.size())
			throw std::invalid_argument("different size.");

		//�i�[��̒�`
		std::string buf(text.size(), 0);

		//���ׂĂ̗v�f�ɑ΂���xor����B
		for (size_t i = 0; i < text.size(); i++)
			buf[i] = text[i] ^ key[i];

		return buf;
	}

	//key�̐���
	std::vector<char> Make_OneTimePad_Key(size_t size, std::function<char(void)> func = []() {return static_cast<char>(rand() % 255); })
	{
		//�T�C�Y������(0�ŏ�����)
		std::vector<char> key(size, 0);

		//����
		for (size_t pos = 0; pos < size; pos++)
			key[pos] = func();

		return key;
	}
}




/*----------�P�ꊷ���Í�----------*/
namespace SSC {
	std::string SSC(const std::string& Text,std::vector<std::pair<char,char>> Dic) {
		//�e�L�X�g�T�C�Y��
		std::string buf(Text.size(),0);

		//�e������ϊ�
		for (size_t i = 0; i < Text.size(); i++) {
			//first����second�ŒT��
			auto Search = std::find_if(Dic.begin(), Dic.end(), [&Text, &i](std::pair<char, char> ele) {return ele.first == Text[i] || ele.second == Text[i]; });

			//������Ȃ��ꍇ
			if (Search == Dic.end())
				throw std::invalid_argument("Not Found.");

			//first�Ō��������ꍇsecond
			if ((*Search).first == Text[i])
				buf[i] = (*Search).second;
			//second�Ō��������ꍇfirst�ɂ���
			else
				buf[i] = (*Search).first;
		}

		return buf;
	}

	//�P�ꊷ���\���쐬����B(�����Ƃ��Ĕ͈͂�����B��:A~z)
	template<typename Engine = std::mt19937>
	std::vector<std::pair<char, char>> MakeDic(char first, char last, Engine engine)
	{
		//first�̕����傫���ꍇ����ւ�
		if (last < first)
			std::swap(last,first);

		//first~last�Ȃ̂�last-first�̎���+1����B
		const auto range = [&first,&last]()->size_t {return static_cast<size_t>(last - first) + 1; };

		//��̎��ł��Ȃ��̂Ŕ͈͂𑝉�
		if (range() & 1)
			last++;

		//first~last�܂Ő��l������
		std::vector<char> buf(range());
		for (size_t i = 0; i < range(); i++)
			buf[i] = first + i;

		//�V���b�t������B
		std::shuffle(buf.begin(),buf.end(),engine);

		//�����ɂ���
		const size_t halfsize = range() / 2;

		//�Ή�������̂ŃT�C�Y�͔����ł���
		std::vector<std::pair<char, char>> ret(halfsize);
		for (size_t i = 0; i < halfsize;i++)
			ret[i] = std::pair<char, char>{buf[i],buf[halfsize+i]};

		return ret;
	}
}




/*----------DES�Í�----------*/
namespace DES {
	
	//left��right�ɕ�����B
	std::pair<uint32_t, uint32_t> split(uint64_t value) {
		return { static_cast<uint32_t>(value >> 32),static_cast<uint32_t>(value) };
	}

	uint32_t DefaultRoundFunc(uint32_t value,std::bitset<48> subkey) {
		std::bitset<48> value_bit = value;
		
		//subkey�Ƃ�xor���Ƃ�B
		value_bit ^= subkey;
		
		//32bit�֐��`
		std::string value_bit_string = value_bit.to_string();
		value_bit_string.erase(value_bit_string.begin(),value_bit_string.begin()+16);

		return std::bitset<32>(value_bit_string).to_ulong();
	}

	//SubKey��48bit�ɂ��邱��!
	template<uint64_t SubKey>
	uint64_t FeistelNode(uint64_t In, std::function<uint32_t(uint32_t, uint32_t)> RoundFunc = DefaultRoundFunc)
	{
		//�\��������
		auto [left, right] = split(In);

		left ^= RoundFunc(right,std::bitset<48>(SubKey));

		return (static_cast<uint64_t>(left) << 32) | right;
	}

	//parity���`�F�b�N����B
	bool CheckParityBit(uint64_t Data,bool EvenNumParity = true) 
	{
		//1�̐����擾
		const size_t SetCount = std::bitset<64>(Data).count();

		//�ُ�Ȏ�false��Ԃ��B
		return EvenNumParity?(SetCount%2==0):(SetCount%2==1);
	}

	//ReducedTransposition(�k���]�u) Parity�`�F�b�N,Parity�폜
	std::bitset<56> RTP(uint64_t Data) 
	{
		//parity���ُ�Ȏ�throw
		if (!CheckParityBit(Data))
			throw std::runtime_error("Parity Error!");

		//parity���폜
		std::string DataBit = std::bitset<64>(Data).to_string();
		for (size_t DelPos = 7; DelPos < 64; DelPos += 8)
			DataBit.erase(DelPos);
		
		//�Ĕz�u
		std::shuffle(DataBit.begin(),DataBit.end(),std::mt19937(255));

		return std::bitset<56>(DataBit);
	}


	//���񍶃r�b�g�V�t�g
	template<size_t C>
	std::bitset<C> CShiftL(std::bitset<C>& Arg,size_t Count)
	{
		return (Arg << Count) | (Arg >> (C-Count));
	}
	//����E�r�b�g�V�t�g
	template<size_t C>
	std::bitset<C> CShiftR(std::bitset<C>& Arg,size_t Count) 
	{
		return (Arg >> Count) | (Arg << (C-Count));
	}


	//SubKey����
	template<size_t Count>
	std::vector<std::bitset<48>> MakeSubKey(uint64_t Key) 
	{
		std::vector<std::bitset<48>> ret;

		std::bitset<56> buf = RTP(Key);

		for (size_t i = 0; i < Count;i++) {
			std::bitset<28> left = buf >> 28,right = (std::bitset<28>)buf;
			left  = CShiftL(left,2);
			right = CShiftR(right,2);

			buf = ((std::bitset<56>)left << 28) | (std::bitset<56>)right;

			ret.push_back(std::bitset<48>(buf));
		}
		
		return ret;
	}

}




#endif