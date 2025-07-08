package com.ltsllc.jceutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;

/**
 * Created by Clark on 6/28/2017.
 */
public class UtilsTest {
    @Test
    public void testEncryption() throws Exception {
        File file = new File("whatever");
        PublicKey publicKey = null;
        PublicKey otherPublicKey = null;

        try {
            Security.addProvider(new BouncyCastleProvider());
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
    public void testLoadKey() {
        int whatever = 13;
        whatever++;
    }

    @org.junit.jupiter.api.Test
    void loadCertificate() {
    }

    @org.junit.jupiter.api.Test
    void loadKeyStore() {
    }

    @org.junit.jupiter.api.Test
    void closeIgnoreExceptions() {
    }

    @org.junit.jupiter.api.Test
    void testCloseIgnoreExceptions() {
    }

    @org.junit.jupiter.api.Test
    void testCloseIgnoreExceptions1() {
    }

    @org.junit.jupiter.api.Test
    void testCloseIgnoreExceptions2() {
    }

    @org.junit.jupiter.api.Test
    void testCloseIgnoreExceptions3() {
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