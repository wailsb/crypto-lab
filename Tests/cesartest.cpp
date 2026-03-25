#include <gtest/gtest.h>
#include "../Classiques/Cesar/cesar.h"

TEST(CesarTest, BasicEncryption) {
    EXPECT_EQ(cesar_crypt("ABC", 3), "DEF");
}

TEST(CesarTest, BasicDecryption) {
    EXPECT_EQ(cesar_decrypt("DEF", 3), "ABC");
}