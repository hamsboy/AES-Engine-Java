/*
This Program implement the Advance Encryption Standard  as defined by NIST(National Institute of Standards and  Technology)
FIPS PUB 197)
The data block size is 128-bits
The lengths used are 128-bits and 256-bits
Date:6/20/2020
@Author:Hamidou Diallo
*/

public class AES{
  //Private instances
  private char[][] state;
  private char[][] key;
  private int Nb;
  private int Nr;
  private int keyLength;
  private char [] expendedKey;
  private String encrypedMessage;
  private String decrypedMessage;

  //========================================================Constructors===============================================================================================
  /*
  We have two constructors: The first one is defualt constructors to AES-128;
  The second constructor takes the Key Length as argument
  */
  public AES(){
    Nb=4;
    Nr=10;
    this.keyLength=128;
    expendedKey=new char[Nb*Nb*(Nr+1)];
    encrypedMessage="";
    decrypedMessage="";
  }

  public AES(int keyLength){
    this.keyLength=keyLength;
    encrypedMessage="";
    decrypedMessage="";
    if(keyLength==128) {
      Nb=4;
      Nr=10;
      expendedKey=new char[Nb*Nb*(Nr+1)];
    }else if(keyLength==256){
      Nb=4;
      Nr=14;
      expendedKey=new char[Nb*Nb*(Nr+1)];
    }else{
      throw new IllegalArgumentException("The Key size should be 128 or 256");
    }
  }
  //==============================================================================================================================================================================


  //========================================================Getters/Setters=======================================================================================================
  public int getKeyLength(){
    return this.keyLength;
  }
  public char[] getexpandedKey(){
    return this.expendedKey;
  }
  public String getDecryptedMessage(){
    return this.decrypedMessage;
  }
  public String getEncryptedMessage(){
    return this.encrypedMessage;
  }
  public void setKeyLength(int keyLength){
    this.keyLength=keyLength;
  }
  //=======================================================================================================================================================

  //========================================================Encryption===============================================================================================
  /*
  */
  public void Encrypt(String input, String mykey){
    if(mykey.trim().length()!=keyLength/8 ){
      throw new IllegalArgumentException("The Key Length should be 128 or 256");
    }

    //key=stringToArray(mykey);
    String message=paddMessage(input);
    int count=0;
    //System.out.println(message);
    int len=message.length()/(Nb*Nb);
    expandKey(mykey);
    for(int i=0;i<len;i++){
      String temp="";
      for(int j=0;j<(Nb*Nb);j++){
        temp+=message.charAt(count++);
      }

      state=stringToArray(temp);
      encrypt(state);
      encrypedMessage+=arrayToString(state);
    }
  }

  private void encrypt(char[][] state){

    addRoundKey(state,0);
    int i;
    for(i=1;i<Nr;i++){
      subByte(state);
      shiftRow(state);
      mixColumn(state);
      // System.out.println(index);
      addRoundKey(state,i);
    }


    subByte(state);
    shiftRow(state);
    addRoundKey(state,i);


  }


  private void subByte(char[][] state){
    int i, j;
    char t;
    for (i = 0; i < Nb; i++)
    {
      for (j = 0; j <Nb; j++)
      {
        t = state[i][j];
        state[i][j] =(char) sbox[((t & 0xf0)>>4)*0x10+ (t & 0x0f)];
      }
    }

  }
  /*
  Add Round Key which is exclusive oring the state with Key
  */
  private void addRoundKey(char[][] state,int index){

    key=arrayToMatrix(index);
    for(int i=0;i<Nb;i++){
      for(int j=0;j<Nb;j++){
        state[j][i]=(char)(state[j][i]^key[j][i]);
      }
    }
  }
  private void shiftRow(char[][] state){
    int i,j;
    char t,t2,t3,t4;
    for (i = 1; i < Nb; i++)
    {
      j=0;
      if(i==1){

        t = state[i][j];

        state[i][j]=state[i][++j];
        state[i][j]=state[i][++j];
        state[i][j]=state[i][++j];
        state[i][j]=t;
      }else if(i==2){

        t = state[i][j++];
        t2 = state[i][j++];
        t3 = state[i][j++];
        t4 = state[i][j];
        j=0;
        state[i][j++]=t3;
        state[i][j++]=t4;
        state[i][j++]=t;
        state[i][j++]=t2;
      }else{
        t = state[i][j++];
        t2 = state[i][j++];
        t3 = state[i][j++];
        t4 = state[i][j];
        j=0;
        state[i][j++]=t4;
        state[i][j++]=t;
        state[i][j++]=t2;
        state[i][j++]=t3;

      }
      j=0;
    }
  }
  /*
  Mix collumn consist of multiplying the the state with a fixed matrix
  the operation involves multiplication by one, by two which shifting left by 2,
  by 3 which is shifting left by 3 and xoring by it value.
  These operations are done in the  galois field.
  */




  private void mixColumn(char[][] state){
    char[] s=new char[Nb];
    char[] s1=new char[Nb];
    int i, j;

    for (j = 0; j < Nb; j++)
    {
      for (i = 0; i < Nb; i++)
      {
        s[i] = state[i][j];
      }

      s1[0] = (char)( multiply((char)0x02, s[0]) ^  multiply((char)0x03, s[1]) ^ s[2] ^ s[3]);
      s1[1] = (char)(s[0] ^  multiply((char)0x02, s[1]) ^ multiply((char)0x03, s[2]) ^ s[3]);
      s1[2] = (char)(s[0] ^ s[1] ^  multiply((char)0x02, s[2]) ^ multiply((char)0x03, s[3]));
      s1[3] =(char)( multiply((char)0x03, s[0]) ^ s[1] ^ s[2] ^  multiply((char)0x02, s[3]));
      for (i = 0; i < 4; i++)
      {
        if(s1[i]<256){
          state[i][j] = s1[i];
        }else{
          state[i][j]=(char)(s1[i]^(0x100));
        }
      }

    }

  }
  //=======================================================================================================================================================


  //========================================================Decryption===============================================================================================

  /*
  Decryption
  */
  public void Decrypt(){
    String input= encrypedMessage;
    // if(mykey.trim().length()!=keyLength/8 ){
    //   throw new IllegalArgumentException("The Key Length should be 128 or 256");
    // }
    //key=stringToArray(mykey);
    String message=paddMessage(input);
    int count=0;
    // System.out.println(message);
    int len=message.length()/(Nb*Nb);
    reverseExpendedKey();
    for(int i=0;i<len;i++){
      String temp="";
      for(int j=0;j<(Nb*Nb);j++){
        temp+=message.charAt(count++);
      }

      state=stringToArray(temp);
      decrypt(state);
      decrypedMessage+=arrayToString(state);


    }
  }



  public void Decrypt( String input,String mykey){


    if(mykey.trim().length()!=keyLength/8 ){
      throw new IllegalArgumentException("The Key Length should be 128 or 256");
    }

    //key=stringToArray(mykey);
    String message=paddMessage(input);
    int count=0;
    // System.out.println(message);
    int len=message.length()/(Nb*Nb);
    expandKey(mykey);
    reverseExpendedKey();
    for(int i=0;i<len;i++){
      String temp="";
      for(int j=0;j<(Nb*Nb);j++){
        temp+=message.charAt(count++);
      }
      state=stringToArray(temp);
      decrypt(state);
      decrypedMessage+=arrayToString(state);
    }
  }




  private void decrypt(char[][] state){

    addRoundKey(state,0);
    int i;
    for(i=1;i<Nr;i++){
      invShiftRow(state);
      invSubByte(state);
      addRoundKey(state,i);
      invMixColumn(state);
      // System.out.println(index);

    }


    invShiftRow(state);
    invSubByte(state);
    addRoundKey(state,i);
  }


  private void invShiftRow(char[][] state){
    int i,j;
    char t,t2,t3,t4;
    for (i = 1; i < Nb; i++)
    {
      j=0;
      if(i==1){
        t = state[i][j++];
        t2 = state[i][j++];
        t3 = state[i][j++];
        t4 = state[i][j];
        j=0;
        state[i][j++]=t4;
        state[i][j++]=t;
        state[i][j++]=t2;
        state[i][j++]=t3;
      }else if(i==2){

        t = state[i][j++];
        t2 = state[i][j++];
        t3 = state[i][j++];
        t4 = state[i][j];
        j=0;
        state[i][j++]=t3;
        state[i][j++]=t4;
        state[i][j++]=t;
        state[i][j++]=t2;
      }else{
        t = state[i][j++];
        t2 = state[i][j++];
        t3 = state[i][j++];
        t4 = state[i][j];
        j=0;
        state[i][j++]=t2;
        state[i][j++]=t3;
        state[i][j++]=t4;
        state[i][j++]=t;

      }
      j=0;
    }
  }



  private void invSubByte(char[][] state){
    int i, j;
    char t;
    for (i = 0; i < Nb; i++)
    {
      for (j = 0; j <Nb; j++)
      {
        t = state[i][j];
        state[i][j] =(char) inv_sbox[((t & 0xf0)>>4)*0x10+ (t & 0x0f)];
      }
    }

  }

  private void invMixColumn(char[][] state){
    char[] s=new char[Nb];
    char[] s1=new char[Nb];
    int i, j;

    for (j = 0; j < Nb; j++)
    {
      for (i = 0; i < Nb; i++)
      {
        s[i] = state[i][j];
      }
      s1[0] =(char)(multiply((char)0x0e, s[0]) ^ multiply((char)0x0b, s[1]) ^ multiply((char)0x0d, s[2]) ^ multiply((char)0x09, s[3]));
      s1[1] = (char)(multiply((char)0x09, s[0]) ^ multiply((char)0x0e, s[1]) ^ multiply((char)0x0b, s[2]) ^ multiply((char)0x0d, s[3]));
      s1[2] =(char)(multiply((char)0x0d, s[0]) ^ multiply((char)0x09, s[1]) ^ multiply((char)0x0e, s[2]) ^ multiply((char)0x0b, s[3]));
      s1[3] =(char)(multiply((char)0x0b, s[0]) ^ multiply((char)0x0d, s[1]) ^ multiply((char)0x09, s[2]) ^ multiply((char)0x0e, s[3]));
      for (i = 0; i < Nb; i++)
      {
        if(s1[i]<256){
          state[i][j] = s1[i];
        }else{
          state[i][j]=(char)(s1[i]^(0x100));
        }
      }

    }
  }




  //===============================================================================================================================================================


  //========================================================Helper Functions===============================================================================================
  /*
  The function are use as utility functions for the AES  Engine
  */
  private char[][] stringToArray(String str){
    char[][] ans=new char[Nb][Nb];
    int index=0;
    for(int i=0;i<Nb;i++){
      for(int j=0;j<Nb;j++){
        ans[j][i]=str.charAt(index++);
      }
    }
    return ans;
  }

  private char multiply(char a, char b) {
    char returnValue = 0;
    char temp = 0;
    while (a != 0) {
      if ((a & 1) != 0)
      returnValue = (char) (returnValue ^ b);
      temp = (char) (b & 0x80);
      b = (char) (b << 1);
      if (temp != 0)
      b = (char) (b ^ 0x1b);
      a = (char) ((a & 0xff) >> 1);
    }
    return returnValue;
  }


  private void reverseExpendedKey(){
    char[] temp=new char[Nb*Nb*(Nr+1)];
    int temp2=0;
    int index=Nb*Nb*(Nr+1);
    for(int i=0;i<(Nb*Nb*(Nr+1));i++){

      if(i%(Nb*Nb)==0){
        //if(i!=0) index-=Nb*Nb;
        temp2+=(Nb*Nb);
        index=(Nb*Nb*(Nr+1))-temp2;

        // System.out.println("temp2:"+temp2);
        // System.out.println(index);

        if(index<0){
          break;
        }
      }
      temp[i]=expendedKey[index++];
    }

    for(int i=0;i<(Nb*Nb*(Nr+1));i++){
      expendedKey[i]=temp[i];
    }
  }
  private char[][]  arrayToMatrix(int index){
    index=index*Nb*Nb;
    char[][] ans=new char[Nb][Nb];
    for(int i=0;i<Nb;i++){
      for(int j=0;j<Nb;j++){
        ans[j][i]= expendedKey[index++];
      }
    }
    return ans;

  }
  private String arrayToString(char[][] arr){
    String ans="";
    for(int i=0;i<Nb;i++){
      for(int j=0;j<Nb;j++){
        ans+=arr[j][i];
      }
    }
    return ans;
  }



  private String paddMessage(String str){
    String message="";
    int len=str.length();
    if(len<(Nb*Nb)){
      message+=str;
      for(int i=len;i<(Nb*Nb);i++){
        message+=" ";
      }
    }else{
      int remainder=len%(Nb*Nb);

      if(remainder>0){
        message+=str;
        for(int i=0;i<(Nb*Nb)-remainder;i++){
          message+=" ";
        }
      }else{
        message=str;
      }
    }
    return message;
  }

  public String hexToAscii(String hex)
  {
    String ans = "";

    for (int i = 0; i < hex.length(); i += 2) {
      String h = hex.substring(i, i + 2);
      char c = (char)Integer.parseInt(h, 16);
      ans+= c;
    }

    return ans;
  }
  //=======================================================================================================================================================



  /*
  The key Schedue which includes the key Expansion
  */
  //========================================================Key Expansion===============================================================================================
  private void expandKey(String keys){

    int generatedBytes=(keyLength/8);


    for(int i=0;i<(keyLength/8);i++){
      expendedKey[i]=keys.charAt(i);
    }

    int rConst=1;
    char [] temp=new char[Nb];

    while(generatedBytes<(Nb*Nb*(Nr+1))){

      for(int j=0;j<Nb;j++){
        temp[j]=expendedKey[j+generatedBytes-Nb];
      }
      if(generatedBytes%(keyLength/8)==0){
        //Rotate row left
        char t=temp[0];
        temp[0]=temp[1];
        temp[1]=temp[2];
        temp[2]=temp[3];
        temp[3]=t;
        //sub bytes

        temp[0]=(char) sbox[(temp[0] / (Nb*Nb))*0x10+ (temp[0]% (Nb*Nb))];
        temp[1]=(char) sbox[(temp[1] / (Nb*Nb))*0x10+ (temp[1]% (Nb*Nb))];
        temp[2]=(char) sbox[(temp[2] / (Nb*Nb))*0x10+ (temp[2]% (Nb*Nb))];
        temp[3]=(char) sbox[(temp[3] / (Nb*Nb))*0x10+ (temp[3]% (Nb*Nb))];

        //rotation constant
        temp[0]=(char)(temp[0]^rcon[rConst++]);

      }
      if(generatedBytes%(keyLength/8)==(Nb*Nb)) {
        for(int a = 0; a < Nb; a++) {
          temp[a] = (char) sbox[(temp[a] / (Nb*Nb))*0x10+ (temp[a]% (Nb*Nb))];
        }
      }

      for(int i=0;i<Nb;i++){
        expendedKey[generatedBytes]=(char)(expendedKey[generatedBytes-(keyLength/8)]^temp[i]);
        generatedBytes++;
      }


    }

  }

  //=========================================================================================================================================================================

  /*
  Printing the Results of Encryption or Decryption
  */


  //========================================================Printing Results===============================================================================================
  public void printEncryption(){
    System.out.print("The Encryption result  in HEX:  ");
    for(int i=0;i<encrypedMessage.length();i++){
      System.out.print(Integer.toHexString((int) encrypedMessage.charAt(i))+" ");
    }
    System.out.println();
    System.out.print("The Encryption result  in ASCII: ");
    System.out.println(encrypedMessage);

  }

  public void printDecryption(){
    System.out.print("The Decryption result in HEX:  ");
    for(int i=0;i<decrypedMessage.length();i++){
      System.out.print(Integer.toHexString((int) decrypedMessage.charAt(i))+" ");
    }
    System.out.println();
    System.out.print("The Decryption result  in ASCII: ");
    System.out.println(decrypedMessage);
    
  }

  public void printKeys(){
    System.out.println();
    for(int i=0;i<Nb*Nb*(Nr+1);i++){
      if(i%(keyLength/8)==0){
        System.out.println();
        System.out.print("Round "+ i/Nb*Nb+": ");
      }
      System.out.print(Integer.toHexString((int) expendedKey[i])+" ");

    }
  }

  //============================================================================================================================================================================




  private int[] sbox= {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };
  private int[] inv_sbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, };

    char[] rcon= {
      0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
      0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
      0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
      0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
      0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
      0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
      0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
      0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
      0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
      0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
      0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
      0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
      0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
      0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
      0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
      0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};


    }
