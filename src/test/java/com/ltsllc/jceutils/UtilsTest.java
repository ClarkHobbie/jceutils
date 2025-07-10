package com.ltsllc.jceutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
// import sun.security.ssl.TrustManagerFactoryImpl;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

// import static sun.security.ssl.TrustManagerFactoryImpl.*;

/**
 * Created by Clark on 6/28/2017.
 */
public class UtilsTest {
    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testReadPublicKeyFromPem() throws Exception {
        File file = new File("whatever");
        PublicKey publicKey = null;
        PublicKey otherPublicKey = null;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            Utils.writeAsPem("whatever", publicKey);

            otherPublicKey = Utils.readPublicKeyFromPem("whatever");
        } finally {
            file.delete();
        }

        assert (publicKey.equals((otherPublicKey)));
    }

    @Test
    public void testLoadCertificate() throws Exception {
        File file = new File("whatever");
        PublicKey publicKey = null;
        PublicKey otherPublicKey = null;
        Certificate certificate = null;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        certificate = Utils.selfSign(keyPair, "dn=whatever");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] password = "whatever".toCharArray();
        keyStore.load (null, null);
        keyStore.setCertificateEntry("certificate", certificate);
        Certificate otherCert = keyStore.getCertificate("certificate");

        assert (certificate.equals(otherCert));
    }

    public static X509Certificate loadCertificate(String filename, String passwordString, String alias)
            throws GeneralSecurityException, IOException {
        X509Certificate certificate = null;
        FileInputStream fileInputStream = null;

        try {
            fileInputStream = new FileInputStream(filename);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fileInputStream, passwordString.toCharArray());
            certificate = (X509Certificate) keyStore.getCertificate(alias);
        } finally {
            fileInputStream.close();
        }

        return certificate;
    }



    @Test
    public void testLoadKeyStore() throws Exception {
        String filename = "whatever";
        String password = "whatever";
        String certAlias = "certificate";
        Certificate certificate = null;
        Certificate otherCert = null;

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            certificate = Utils.selfSign(keyPair, "dn=whatever");
            keyStore.load(null, null);
            keyStore.setCertificateEntry(certAlias, certificate);

            Utils.storeKeyStore(keyStore, filename, password);

            otherCert = Utils.loadCertificate(filename, password, certAlias);
        } finally {
            File file = new File(filename);
            if (file.exists())
                file.delete();
        }

        assert (certificate.equals(otherCert));
    }

    @Test
    public void testCloseIgnoreExceptions() throws Exception {
        String filenameExisting = "whatever";
        File existingFile = new File(filenameExisting);
        String nonExistingFileName = "no exist";
        File nonExistingFile = new File(nonExistingFileName);
        Exception exception = null;

        try {
            if (!existingFile.exists()) {
                existingFile.createNewFile();
            }

            FileInputStream fileInputStream = new FileInputStream(existingFile);
            try {
                Utils.closeIgnoreExceptions(fileInputStream);
            } catch (Exception e) {
                exception = e;
            }

            if (nonExistingFile.exists()) {
                nonExistingFile.delete();
            }

            fileInputStream = null;
            try {
                Utils.closeIgnoreExceptions(fileInputStream);
            } catch (Exception e) {
                exception = e;
            }
        } finally {
            if (existingFile.exists())
                existingFile.delete();

            if (nonExistingFile.exists())
                nonExistingFile.delete();
        }

        assert (exception == null);
    }

    @Test
    public void testCloseIgnoreExceptions1() throws Exception {
        //
         // test it with an OutputStream
        //
        File file = new File("whatever");
        if (file.exists())
            file.delete();
        Exception exception = null;
        FileOutputStream fileOutputStream = null;

        try {
            fileOutputStream = new FileOutputStream(file);
            Utils.closeIgnoreExceptions(fileOutputStream);
            fileOutputStream.close();

            fileOutputStream = null;
            Utils.closeIgnoreExceptions(fileOutputStream);
        } catch (Exception e) {
            exception = e;
        } finally {
            if (file.exists())
                file.delete();

            if (fileOutputStream != null) {
                fileOutputStream.close();
            }
        }

        assert (exception == null);
    }

    @Test
    public void testCloseIgnoreExceptions2() throws Exception {
        //
         // test for a reader
        //
        File file = new File("whatever");
        if (!file.exists())
            file.createNewFile();
        Exception exception = null;
        FileReader fileReader = null;

        try {
            fileReader = new FileReader(file);
            Utils.closeIgnoreExceptions(fileReader);

            fileReader = null;
            Utils.closeIgnoreExceptions(fileReader);
        } catch (IOException e) {
            exception = e;
        } finally {
            if (file.exists())
                file.delete();

            if (fileReader != null) {
                fileReader.close();
            }
        }

        assert (exception == null);

    }

    @Test
    public void testCloseIgnoreExceptions3() throws Exception {
        //
        // test for a reader
        //
        File file = new File("whatever");
        if (!file.exists())
            file.delete();
        Exception exception = null;
        FileWriter fileWriter = null;

        try {
            fileWriter = new FileWriter(file);
            Utils.closeIgnoreExceptions(fileWriter);

            fileWriter = null;
            Utils.closeIgnoreExceptions(fileWriter);
        } catch (IOException e) {
            exception = e;
        } finally {
            if (file.exists())
                file.delete();

            if (fileWriter != null) {
                fileWriter.close();
            }
        }

        assert (exception == null);
    }

    @Test
    public void testCloseReturnExceptions() throws Exception {
        String message = null;

        File file = new File("whatever");
        if (!file.exists())
            file.createNewFile();

        FileInputStream fileInputStream = new FileInputStream(file);
        fileInputStream = null;
        message = Utils.closeReturnExceptions(fileInputStream);

        //
         // couldn't find a way of making FileInputStream on throwing an exception on close.
        //
        // assert (message != null);
    }

    @Test
    public void testCloseReturnExceptions1() throws Exception {
        //
         // try it with an output stream
        //
        File file = new File("whatever");
        if (file.exists())
            file.delete();

        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.close();;

        String message = null;
        try {
            Utils.closeReturnExceptions(fileOutputStream);
        } catch (Exception e) {
            message = e.getMessage();
        }

        if (file.exists())
            file.delete();

        //
         // couldn't figure out how to get fileOutputStream to throw an Exception on close
        //
        // assert (message != null);
    }

    @Test
    public void testCalculateSha256() throws Exception {
        File file = new File("constitution.txt");
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] sha256 = Utils.calculateSha256(fileInputStream);
        String expectedString = "B2EF2B846B8CDAD268D50AE8493ADB772502704B867E0550FBB3BDB51A93EAC4";
        byte[] expected = HexConverter.toByteArray(expectedString);
        assert (sha256 != null);
        assert (Arrays.equals(sha256, expected));
    }

    @Test
    public void testByteToHexString() {
        byte[] bytes = { 1,2,3 };
        String string = Utils.byteToHexString((byte) 1);

        assert (string.equalsIgnoreCase("01"));
    }

    @Test
    public void testBytesToString() {
        byte[] bytes = { 1,2,3 };
        String string = Utils.bytesToString(bytes);

        assert (string.equalsIgnoreCase("010203"));
    }

    @Test
    public void testInputStreamToHexString() throws Exception {
        byte[] bytes = { 1,2,3 };
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        String string = Utils.inputStreamToHexString(bais);

        assert (string.equalsIgnoreCase("010203"));
    }

    @Test
    public void testReadInputStream() throws Exception {
        byte[] bytes = { 1,2,3 };
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        String string = Utils.inputStreamToString(bais);

        assert (string.equalsIgnoreCase("123"));
    }

    @Test
    public void testEncrypt() throws Exception {
        String clearText = "This is a confidential message.";

        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        // Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        keyGenerator.init(56);
        Key key = keyGenerator.generateKey();
        String algorithm = "DES/ECB/PKCS5Padding";

        String cipherText = Utils.encrypt(algorithm, key, clearText);

        String result = Utils.decrypt(algorithm, key, cipherText);


        // Verify that the decryption was successful
        assert (clearText.equals(result));
    }

    @Test
    public void testHexStringToBytes() throws IOException {
        String string = "010203";
        byte[] bytes = Utils.hexStringToBytes(string);
        byte[] expected = { 1, 2, 3 };
        assert (Arrays.equals(bytes, expected));
    }

    @Test
    public void testToByte() {
        char[] input = { '0', '1' };
        byte expected = 1;
        byte result = Utils.toByte(input);
        assert (result == expected);
    }

    @Test
    public void testToNibble() {
        int result = Utils.toNibble('a');
        assert (result == 10);

        result = Utils.toNibble('1');
        assert (result == 1);
    }

    @Test
    public void testToBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.order(ByteOrder.BIG_ENDIAN); // Or ByteOrder.LITTLE_ENDIAN
        buffer.putLong(1); // Put the long value into the buffer
        byte[] expected = buffer.array(); // Return the underlying byte array

        byte[] bytes = Utils.toBytes(1);

        assert (Arrays.equals(bytes, expected));
    }

    @org.junit.jupiter.api.Test
    void pemStringToPublicKey() {
    }

    @org.junit.jupiter.api.Test
    void publicKeyToPemString() {
    }

    @org.junit.jupiter.api.Test
    void createPublicKeyPem() {
    }

    @org.junit.jupiter.api.Test
    void writeAsPem() {
    }

    @org.junit.jupiter.api.Test
    void testWriteAsPem() {
    }

    @org.junit.jupiter.api.Test
    void rsaEncrypt() {
    }

    @org.junit.jupiter.api.Test
    void testWriteAsPem1() {
    }

    @org.junit.jupiter.api.Test
    void readAsString() {
    }

    @org.junit.jupiter.api.Test
    void convertPemStringToPublicKey() {
    }

    @org.junit.jupiter.api.Test
    void readBytes() {
    }

    @org.junit.jupiter.api.Test
    void toStacktrace() {
    }

    @org.junit.jupiter.api.Test
    void readTextFile() {
    }

    @org.junit.jupiter.api.Test
    void writeTextFile() {
    }

    @org.junit.jupiter.api.Test
    void toPem() {
    }

    @org.junit.jupiter.api.Test
    void testToPem() {
    }

    @org.junit.jupiter.api.Test
    void stringsAreEquivalent() {
    }

    @org.junit.jupiter.api.Test
    void stringListsAreEquivalent() {
    }

    @org.junit.jupiter.api.Test
    void toEquivalentList() {
    }

    @org.junit.jupiter.api.Test
    void hexEncode() {
    }

    @org.junit.jupiter.api.Test
    void hexDecode() {
    }

    @org.junit.jupiter.api.Test
    void bothEqualCheckForNull() {
    }

    @org.junit.jupiter.api.Test
    void selfSign() {
    }
}