package com.ltsllc.jceutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.BeforeAll;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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

    @org.junit.jupiter.api.Test
    void exceptionToString() {
    }

    @org.junit.jupiter.api.Test
    void closeReturnExceptions() {
    }

    @org.junit.jupiter.api.Test
    void testCloseReturnExceptions() {
    }

    @org.junit.jupiter.api.Test
    void testCloseReturnExceptions1() {
    }

    @org.junit.jupiter.api.Test
    void calculateSha1() {
    }

    @org.junit.jupiter.api.Test
    void byteToHexString() {
    }

    @org.junit.jupiter.api.Test
    void bytesToString() {
    }

    @org.junit.jupiter.api.Test
    void inputStreamToHexString() {
    }

    @org.junit.jupiter.api.Test
    void readInputStream() {
    }

    @org.junit.jupiter.api.Test
    void cipherStreamToString() {
    }

    @org.junit.jupiter.api.Test
    void hexStringToBytes() {
    }

    @org.junit.jupiter.api.Test
    void toByte() {
    }

    @org.junit.jupiter.api.Test
    void toNibble() {
    }

    @org.junit.jupiter.api.Test
    void testCalculateSha1() {
    }

    @org.junit.jupiter.api.Test
    void testCalculateSha11() {
    }

    @org.junit.jupiter.api.Test
    void createTrustManagerFactory() {
    }

    @org.junit.jupiter.api.Test
    void createKeyManagerFactoy() {
    }

    @org.junit.jupiter.api.Test
    void createSocketServerSslContext() {
    }

    @org.junit.jupiter.api.Test
    void hexStringToString() {
    }

    @org.junit.jupiter.api.Test
    void toBytes() {
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