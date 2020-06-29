import java.util.*;
public class AesMain {
  public static void main(String[] args)
  {

    Scanner  input=null;
    while(true){
      System.out.println("Welcome to the Advance Encryption Standard Engine");
      System.out.println("The key length for this engine is 128 or 256");
      System.out.println();
      System.out.println("please Select your key Length 128/256");
      input=new Scanner(System.in);
      int keyLen=input.nextInt();
      while(keyLen!=128 && keyLen!=256){
        System.out.println("The key Length should be 128 or 256"); 
        System.out.println("please Select your key Length 128/256");
        keyLen=input.nextInt();
      }


      AES aes=new AES(keyLen);
      System.out.println();
      System.out.println("Do you want to Encrypt or Decrypt?");
      System.out.println("Press E for Encrypt or D for Decrypt");
      String engine=input.next().trim();
      while(!engine.equals("D") && !engine.equals("E") && !engine.equals("d") && !engine.equals("e")){
        System.out.println("Do you want to Encrypt or Decrypt?");
        System.out.println("Press E for Encrypt or D for Decrypt");
        engine=input.next().trim();
      }

      System.out.println();
      System.out.println("please Enter your key");
      String key=input.nextLine();
      key=input.nextLine();
      while((keyLen/8)!=key.length()){
        System.out.println("The key should be "+ keyLen/8 + " Characters long since one ASCII character represents 1 byte(8-bits)");
        System.out.println("please Enter your key");
        key=input.nextLine();
      }

      if(engine.equals("E") || engine.equals("e")){
        System.out.println();
        System.out.println("please Enter  The text to be Encrypted");
        String plainText=input.nextLine();
        aes.Encrypt(plainText, key);
        System.out.println();
        System.out.println("=========================================================================================================================================================");
        aes.printEncryption();
        System.out.println("=========================================================================================================================================================");
        System.out.println();
        System.out.println("Do you want to Decrypt your Encrypted Message");
        System.out.println("Press Y for yes and N for no");
        String d=input.next().trim();
        while(!d.equals("Y") && !d.equals("y") && !d.equals("n") && !d.equals("N")){
          System.out.println("Do you want to Decrypt your Encrypted Message");
          System.out.println("Press Y for yes and N for no");
          d=input.next().trim();
        }
        if(d.equals("Y") || d.equals("y")){
          //  aes.printKeys();
          aes.Decrypt();
          System.out.println();
          System.out.println("=========================================================================================================================================================");
          aes.printDecryption();
          System.out.println("=========================================================================================================================================================");
          //aes.printKeys();
          System.out.println();
        }
      }else{
        System.out.println("Do want to enter the Hex values or Ascii values?");
        System.out.println("Press H for Hex Values or A for Ascii Values");
        String hex=input.next();
        while(!hex.equals("H") && !hex.equals("h") && !hex.equals("A") && !hex.equals("a")){
          System.out.println("Wrong input!");
          System.out.println("Press H for Hex Values or A for Ascii Values");
          hex=input.next();
        }
        System.out.println();
        System.out.println("please Enter The text to be Decrypted");
        String cipherText=input.nextLine();
        cipherText=input.nextLine();
        if(hex.equals("h") || hex.equals("H")){
          cipherText=aes.hexToAscii(cipherText);
        }
        aes.Decrypt(cipherText, key);
        System.out.println();
        System.out.println("=========================================================================================================================================================");
        aes.printDecryption();
        System.out.println("=========================================================================================================================================================");
        System.out.println();
      }


      System.out.println("Do you want to end the Encryption/Decryption");
      System.out.println("Press Y for yes and N for no");
      String end=input.next().trim();
      while(!end.equals("Y") && !end.equals("y") && !end.equals("n") &&!end.equals("N")){
        System.out.println("Do you want to end the Encryptioyn/Decryption");
        System.out.println("Press Y for yes and N for no");
        end=input.next().trim();
      }
      if(end.equals("Y") || end.equals("y")){
        break;
      }
      System.out.println("===========================================y==============================================================================================================");
      System.out.println();




    }
    input.close();
  }

}
