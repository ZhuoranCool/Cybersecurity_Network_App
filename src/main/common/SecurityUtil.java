package main.common;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.mindrot.jbcrypt.BCrypt;

public class SecurityUtil {
    //SHA-256 Hashing
    public static String sha256(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
            Formatter formatter = new Formatter();
            for (byte b : digest) formatter.format("%02x", b);
            String out = formatter.toString();
            formatter.close();
            return out;
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 failure", e);
        }
    }


    //RSA Key Pair Generation (2048 bits)
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    //RSA Encryption (OAEP)
    public static byte[] rsaEncryptOAEP(byte[] plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    //RSA Decryption (OAEP)
    public static byte[] rsaDecryptOAEP(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    //AES-256 Key Generation
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    //AES-GCM Encryption
    public static byte[] aesGcmEncrypt(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(plaintext);
    }

    //AES-GCM Decryption
    public static byte[] aesGcmDecrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(ciphertext);
    }

    //RSA-PSS Signature Generation (SHA-256)
    public static byte[] rsaSignPSS(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    //RSA-PSS Signature Verification (SHA-256)
    public static boolean rsaVerifyPSS(byte[] data, byte[] sig, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sig);
    }

    //Bcrypt Password Hashing 
    public static String bcryptHash(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    //Bcrypt Password Verification
    public static boolean bcryptCheck(String password, String hash) {
        return BCrypt.checkpw(password, hash);
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }

        public static void savePublicKey(PublicKey publicKey, String path) throws Exception {
        Path p = Path.of(path);
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        Files.write(p, publicKey.getEncoded());
    }

    public static void savePrivateKey(PrivateKey privateKey, String path) throws Exception {
        Path p = Path.of(path);
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        Files.write(p, privateKey.getEncoded());
    }

    public static PublicKey loadPublicKey(String path) throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of(path));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of(path));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
}