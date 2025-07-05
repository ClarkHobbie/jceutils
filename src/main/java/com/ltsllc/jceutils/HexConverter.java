package com.ltsllc.jceutils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/******************************************************************************
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
            stringBuilder.append(toHexString(c));
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
        for (int index = 0; index < s.length(); index++) {
            String subString = s.substring(index, index + 1);
            byte b = toByte(subString);
            baos.write(b);
        }
        return baos.toByteArray();
    }

    public static byte toByte (String string) {
        int index = theChars.indexOf(string.toCharArray()[0]);
        int higNibble = index << 4;
        index = theChars.indexOf(string.toCharArray()[1]);
        byte b = (byte) (higNibble | index);
        return b;
    }
}
