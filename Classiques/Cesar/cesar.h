#pragma once
#include <string>

std::string cesar_crypt(const std::string& plaintext, int k);
std::string cesar_decrypt(const std::string& ciphertext, int k);

