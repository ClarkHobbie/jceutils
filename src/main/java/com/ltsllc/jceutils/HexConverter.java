package com.ltsllc.jceutils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/******************************************************************************
 * A class that converts bytes to hex strings.
 */
public class HexConverter {

    public static String toHexString (byte aByte) {
        StringBuilder stringBuilder;

        stringBuilder = new StringBuilder();
        toHexString(aByte, stringBuilder);
        return stringBuilder.toString();
    }

    private static final String theChars = "0123456789ABCDEF";

    public static String toHexString (int aByte, StringBuilder stringBuilder) {
        byte highOrderNibble1 = (byte) (aByte & 0xF000);
        byte highOrderNibble2 = (byte) (aByte & 0xF00);
        byte lowOrderNibble1 = (byte) (aByte & 0xF0);
        byte lowOrderNibble2 = (byte) (aByte & 0xF);

        stringBuilder.append(theChars.charAt(highOrderNibble1));
        stringBuilder.append(theChars.charAt(highOrderNibble2));
        stringBuilder.append(theChars.charAt(lowOrderNibble1));
        stringBuilder.append(theChars.charAt(lowOrderNibble2));

        return stringBuilder.toString();
    }

    public static String toHexString (InputStreamReader inputStreamReader)
            throws IOException
    {
        StringBuilder stringBuilder2 = new StringBuilder();

        for (int c = inputStreamReader.read(); c != -1; c = inputStreamReader.read())
        {
            stringBuilder2.append(toHexString(c,stringBuilder2));
        }

        return stringBuilder2.toString();
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
