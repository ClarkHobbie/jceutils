package com.ltsllc.jceutils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * A class that converts bytes to hex strings.
 */
public class HexConverter {

    private static final String theChars = "0123456789ABCDEF";

    public static String toHexString (int aByte) {
        StringBuilder stringBuilder = new StringBuilder();
        int firstChar = aByte & 0b11110000;
        firstChar = firstChar >> 4;
        int secondChar = aByte & 0b1111;

        stringBuilder.append(theChars.charAt(firstChar));
        stringBuilder.append(theChars.charAt(secondChar));

        return stringBuilder.toString();
    }

    public static String toHexString (InputStreamReader inputStreamReader)
            throws IOException
    {
        StringBuilder stringBuilder = new StringBuilder();

        for (int c = inputStreamReader.read(); c != -1; c = inputStreamReader.read())
        {
            byte b = (byte) (c & 0xFF);
            stringBuilder.append(toHexString(b));
        }

        return stringBuilder.toString();
    }


    public static String toHexString (byte[] byteArray)
    {
        StringBuilder stringBuilder = new StringBuilder(4 * byteArray.length);
        for (byte current : byteArray)
        {
            String string = toHexString(current);
            stringBuilder.append(string);
        }

        return stringBuilder.toString();
    }


    public static byte[] toByteArray (String s)
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int index = 0; index < s.length(); index = index + 2) {
            String subString = s.substring(index, index + 2);
            byte b = toByte(subString);
            baos.write(b);
        }
        return baos.toByteArray();
    }

    public static byte toByte (String string) {
        if (string.length() < 2) {
            throw new IllegalArgumentException("asked to convert a string for, " + string);
        }
        char c1 = string.charAt(0);
        int index = theChars.indexOf(c1);
        byte highNibble = (byte) (index << 4);
        char c2 = string.charAt(1);
        byte lowNibble = (byte)theChars.indexOf(c2);
        byte result = (byte) (highNibble | lowNibble);

        return result;
    }
}
