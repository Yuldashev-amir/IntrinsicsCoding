// aexCodinIntr.cpp
#include <iostream>
#include <cstdint>
#include <cpuid.h>
#include <wmmintrin.h> 
#include <immintrin.h>

alignas(16) uint8_t dataAes[16] = {0x76, 0x48, 0x2F, 0xAE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

alignas(16) uint8_t keyArr[16] = {0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x79, 0x88,
                               0x97, 0xA6, 0xB5, 0xC4, 0xD3, 0xE2, 0xF1, 0x00};

bool checkAES()
{
	unsigned int eax, ebx, ecx, edx;
	if(!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
		return false;
	return (ecx & (1 << 25));
}

void aes_encryption(uint8_t *dataAes, uint8_t *key) 
{
	if(!dataAes || !keyArr)
	{
		fprintf(stderr, "Error: Invalid data pointers or key!");
		return;
	}

	if(!checkAES)
	{
		fprintf(stderr, "Error: Processor does not support AES-NI!");
		return;
	}

    __m128i key_schedule[11];
    key_schedule[0] = _mm_loadu_si128((__m128i*)keyArr); 
    
    __m128i block = _mm_loadu_si128((__m128i*)dataAes);
    block = _mm_xor_si128(block, key_schedule[0]); 

    for (int i = 1; i < 10; i++) 
    {
        block = _mm_aesenc_si128(block, key_schedule[i]);
    }

    if(_mm_test_all_zeros(block, block))
    {
    	fprintf(stderr, "Error: Encryption resulted in a null block!");
    	return;
    }

    block = _mm_aesenclast_si128(block, key_schedule[10]);
    _mm_storeu_si128((__m128i*)dataAes, block);
}

int main() 
{
    std::cout << "Before encryption: ";
    for (auto b : dataAes) std::cout << std::hex << (int)b << " ";
    std::cout << std::endl;

    aes_encryption(dataAes, keyArr);  

    std::cout << "After encryption: ";
    for (auto b : dataAes) std::cout << std::hex << (int)b << " ";
    std::cout << std::endl;

    return 0;
}