package com.ltsllc.jceutils;

import org.junit.jupiter.api.Test;

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
    }

    @Test
    void testToHexString1() {
    }

    @Test
    void testToHexString2() {
    }

    @Test
    void toByteArray() {
    }

    @Test
    void toByte() {
    }
}