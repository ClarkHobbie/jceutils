package com.ltsllc.jceutils;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class HexConverterTest {

    @Test
    void testToHexString4() {
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
    void testToByteArray() {
        String string = "644064";
        byte[] bytes = HexConverter.toByteArray(string);

        byte[] expected = { 100, 64, 100 };
        assert (Arrays.equals(bytes, expected));
    }

    @Test
    void testToHexString2 () {
        //
         // test HexConverter.toHexString (byte[])
        //
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(32);
        baos.write(100);
        baos.write(35);

        String string = HexConverter.toHexString(baos.toByteArray());

        assert (string.equalsIgnoreCase("206423"));
    }

    @Test
    void testToHexString3 () {
        //
         // test HexConverter.toHexString(InputStreamReader)
        //
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(32);
        baos.write(100);
        baos.write(35);

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        InputStreamReader isr = new InputStreamReader(bais);
        String string = null;
        try {
            string = HexConverter.toHexString(isr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        assert (string.equalsIgnoreCase("206423"));
    }

    @Test
    void testToByte() {
        String test1 = "64";

        byte result = HexConverter.toByte(test1);

        assert (result == 100);

        String test2 = "40";

        result = HexConverter.toByte(test2);

        assert (result == 64);
    }
}