import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class DigitSign {
    public static void main(String[] args) {
        DigitSign digitSign = new DigitSign();
        String key = "sender_keystore.p12";
        String alias ="senderKeyPair";
        char[] pwd = new char[]{'c','h','a','n','g','e','i','t'};
        PrivateKey pk = null;
        try {
            //load the private key
            pk = digitSign.keyLoader(key, alias, pwd);
            System.out.println(pk);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        //load the public key
        PublicKey pubkey = digitSign.getPublicKey(key, alias, pwd);
        System.out.println("Public key");
        System.out.println(pubkey);
        //Hash the message
        byte[] hashedMsg = digitSign.getHash("text.txt");
        System.out.println("Hashed message");
        //System.out.println(hashedMsg);
        for (int i=0;i<hashedMsg.length;i++){
            System.out.print(hashedMsg[i]+" ");
        }
        //encrypt the hashed message
        digitSign.encrypt(hashedMsg, pk);
        byte[] decryptedMsg = digitSign.decrypt("digital_signature_1", pubkey);
        boolean isSame = digitSign.checkHashes(hashedMsg, decryptedMsg);
        if(isSame){
            System.out.println("Message are similar!");
        }

    }
    public static String getPath(String path){
        URL resource = DigitSign.class.getResource(path);
        File file = null;
        try {
            file = Paths.get(resource.toURI()).toFile();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        String keyPath = file.getAbsolutePath();
        return keyPath;
    }
    public PrivateKey keyLoader(String key, String alias, char[] pwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, URISyntaxException {
        String keyPath = getPath(key);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(keyPath),pwd);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pwd);
        return privateKey;
    }
    public PublicKey getPublicKey(String key, String alias, char[] pwd){
        String keyPath = getPath(key);
        PublicKey publicKey = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(keyPath), pwd);
            Certificate certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
        
        return publicKey;
    }
    public byte[] getHash(String messagePath){
        byte[] messageHash = null;
        try {
            byte[] messageBytes = Files.readAllBytes(Paths.get(getPath(messagePath)));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            messageHash = md.digest(messageBytes);
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return messageHash;
    }

    public void encrypt(byte[] messageHash, PrivateKey privateKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] digitalSignature = cipher.doFinal(messageHash);
            Files.write(Paths.get("digital_signature_1"), digitalSignature);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public byte[] decrypt(String encryptedMsg, PublicKey publicKey){
        byte[] decryptedMessage = null;
        try {
            byte[] encryptedMessageHash = Files.readAllBytes(Paths.get(encryptedMsg));
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            decryptedMessage = cipher.doFinal(encryptedMessageHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return decryptedMessage;
    }

    public boolean checkHashes(byte[] decryptedMessageHash, byte[] newMessageHash){
        return Arrays.equals(decryptedMessageHash, newMessageHash);
    }
}
