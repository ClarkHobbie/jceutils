package com.ltsllc.jceutils;

import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

/**
 * Created by Clark on 6/28/2017.
 */
public class UtilsTest {
    @Test
    public void testEncryption() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        Utils.writeAsPem("whatever", publicKey);
    }
}