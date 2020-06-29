
This Program implement the Advance Encryption Standard  as defined by NIST(National Institute of Standards and  Technology)
FIPS PUB 197) in Java.
The suportted  data block size is 128-bits.
This implementation only support key  lengths of  128-bits and 256-bits.

All the layers(Subyte, ShiftRow, MixColumn and AddRoundKey) were test individually before integrating them to the whole system.
I did the testing by using some external websites such as https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf.

You can test using one of following:

Using a test module and feed it with a plain text and a key to our encryption engine to get a cipher text and take cipher text with same key and feed it to the decryption engine to see if we can get the original plain text. You can use the AesMain.java to test the Encryption or Decryption. 

You can text our program using external website designed for testing AES engines. You can give our program an input key and plain text to get a cipher text. Then give the same key and plain text to the website that test AES as input to get a plain text. Compare the two plan texts to see if they are the same. Do the same thing for decryption.One of the websites I used  to test my results was http://aes.online-domain-tools.com/.

	This is the lest efficient way and consist of verifying the result manually.

