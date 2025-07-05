package com.ltsllc.jceutils;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class HexConverterTest {

    @Test
    void toHexString() {
        //
         // test HexConverter.toHexString(byte)
        //
        byte b = 100;
        String string = HexConverter.toHexString(b);

        assert (string.equalsIgnoreCase("64"));
    }

    @Test
    void testToHexString() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        baos.write(100);
        baos.write( 64);
        baos.write(100);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamReader inputStreamReader = new InputStreamReader(bais);
        String string = null;
        try {
            string = HexConverter.toHexString(inputStreamReader);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        assert (string.equalsIgnoreCase("644064"));
    }

    @Test
    void toByteArray() {
        String string = "644064";
        byte[] bytes = HexConverter.toByteArray(string);

        byte[] expected = { 100, 64, 100 };
        assert (Arrays.equals(bytes, expected));
    }

    @Test
    void toByte() {
    }

    @Test
    void testToHexString3() {
    }

    @Test
    void testToByteArray() {
    }
}