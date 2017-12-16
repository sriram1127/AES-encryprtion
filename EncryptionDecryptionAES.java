import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class EncryptionDecryptionAES {
	static Cipher cipher;

	public static void main(String[] args) throws Exception {
		final Date currentTime = new Date();

		final SimpleDateFormat sdf = new SimpleDateFormat(
				"yyyy/dd/MM hh:mm:ss");

		sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
		System.out.println("GMT time: " + sdf.format(currentTime));
		
		String dateTime = sdf.format(currentTime);
		String userName = "admin@uni.com";
		String secretValue = dateTime+userName;
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		
		System.out.println("------");
		String encodedKey =
				 Base64.getEncoder().encodeToString(secretKey.getEncoded());
				 System.out.println(encodedKey);
				 
				 System.out.println("------");
		byte[] key = encodedKey.getBytes();
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
		
		
		// String key = "Bar12345Bar12345";
		// Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
		// SecretKey secretKey1 = keyGenerator.generateKey();

		/* String encodedKey =
		 Base64.getEncoder().encodeToString(secretKey.getEncoded());
		 System.out.println(encodedKey);*/
		cipher = Cipher.getInstance("AES");

		//String plainText = "1443050702555admin@uni.com";
		System.out.println("Plain Text Before Encryption: " + secretValue);
		

		String encryptedText = encrypt(secretValue, secretKeySpec);
		System.out.println("Encrypted Text After Encryption: " + encryptedText);

		String decryptedText = decrypt(encryptedText,secretKeySpec);
		System.out.println("Decrypted Text After Decryption: " + decryptedText);
	}

	public static String encrypt(String plainText, SecretKey secretKey)
			throws Exception {
		byte[] plainTextByte = plainText.getBytes();
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encryptedByte = cipher.doFinal(plainTextByte);
		Base64.Encoder encoder = Base64.getEncoder();
		String encryptedText = encoder.encodeToString(encryptedByte);
		return encryptedText;
	}

	public static String decrypt(String encryptedText, SecretKey secretKey)
			throws Exception {
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] encryptedTextByte = decoder.decode(encryptedText);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
		String decryptedText = new String(decryptedByte);
		return decryptedText;
	}
}





/* package com.example;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
public class StrongAES 
{
    public void run() 
    {
        try 
        {
            String text = "Hello World";
            String key = "Bar12345Bar12345"; // 128 bit key
            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            // encrypt the text
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = cipher.doFinal(text.getBytes());
            System.err.println(new String(encrypted));
            // decrypt the text
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            String decrypted = new String(cipher.doFinal(encrypted));
            System.err.println(decrypted);
        }
        catch(Exception e) 
        {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) 
    {
        StrongAES app = new StrongAES();
        app.run();
    }
}*/