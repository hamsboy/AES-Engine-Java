
This Program implement the Advance Encryption Standard  as defined by NIST(National Institute of Standards and  Technology)
FIPS PUB 197) in Java.
The suportted  data block size is 128-bits.
This implementation only support key  lengths of  128-bits and 256-bits.

All the layers(Subyte, ShiftRow, MixColumn and AddRoundKey) were test individually before integrating them to the whole system.
I did the testing by using some external websites such as https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf.

The susyetem is tested as a whole. You can use the AesMain.java to test the Encryption or Decryption. I used some external websites to test
my results also http://aes.online-domain-tools.com/.


