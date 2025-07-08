package com.ltsllc.jceutils;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

class ImprovedKeyStoreTest {

    @Test
    void testGetPrivateKey() {
        KeyPairGenerator keyPairGenerator = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        Certificate certificate = null;
        try {
            certificate = Utils.selfSign(keyPair, "dn=whatever");
        }
        catch (OperatorCreationException|CertificateException|IOException e) {
            throw new RuntimeException(e);
        }
        Certificate[] certificates = { certificate };
        char[] password = "hi there".toCharArray();
        try {
            keyStore.load(null,null);
            keyStore.setKeyEntry("private", keyPair.getPrivate(), password, certificates);
        } catch (KeyStoreException|IOException|NoSuchAlgorithmException|CertificateException e) {
            throw new RuntimeException(e);
        }

        PrivateKey privateKey = null;
        try {
            privateKey = ImprovedKeyStore.getPrivateKey(keyStore, "private", password);
        } catch (KeyStoreException|NoSuchAlgorithmException|UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }

        assert (privateKey != null);
        assert (privateKey.equals(keyPair.getPrivate()));
   }

    @Test
    void testGetPublicKey() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        Certificate certificate = null;
        try {
            keyStore.load(null, null);
            certificate = Utils.selfSign(keyPair, "dn=whatever");
            keyStore.setCertificateEntry("certificate", certificate);
        } catch (GeneralSecurityException|OperatorCreationException|IOException e) {
            throw new RuntimeException(e);
        }

        PublicKey publicKey = null;

        try {
            publicKey = ImprovedKeyStore.getPublicKey(keyStore,"certificate");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        assert (publicKey != null);
        assert (publicKey.equals (keyPair.getPublic()));
    }
}