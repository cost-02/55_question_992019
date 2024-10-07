package com.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AES256PasswordBasedEncryption {
    public static void main(String[] args) {
        try {
            String password = "your_password_here";  // Sostituisci con la tua password
            byte[] salt = new byte[16];  // Il sale dovrebbe essere generato casualmente e salvato con i dati cifrati
            int iterationCount = 65536;
            int keyLength = 256;

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Esempio di cifratura
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            
            String originalString = "Esempio di testo da cifrare";
            byte[] encrypted = cipher.doFinal(originalString.getBytes());
            System.out.println("Cifrato: " + Base64.getEncoder().encodeToString(encrypted));

            // Esempio di decifratura
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, cipher.getParameters());
            byte[] decrypted = cipher.doFinal(encrypted);
            System.out.println("Decifrato: " + new String(decrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
