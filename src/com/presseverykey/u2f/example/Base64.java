/*
Copyright (c) 2011 Tim Becker. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/


package com.presseverykey.u2f.example;


/**
 * A simplistic Base64 encoder/decode: throw in a byte Array, get a Base64
 * string, toss in a Base64 encoded string, get a byte Array.
 */

public class Base64 {

    /**
     * Encodes the provided byte array to a base64 String.
     * This method should never fail.
     */
    public static String encode(byte[] bytes) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 3) {
            int remain = (bytes.length - i);
            remain = remain > 3 ? 3 : remain;
            switch (remain) {
                case 3:
                    lookup3(buf, bytes, i);
                    break;
                case 2:
                    lookup2(buf, bytes, i);
                    break;
                case 1:
                    lookup1(buf, bytes, i);
                    break;
                default:
                    throw new RuntimeException("impossible"); // seriously.
            }
        }
        return buf.toString();
    }

    /**
     * Decode a base64 encoded String to a byte array.
     * <p/>
     * This method will throw an IllegalArgumentException in case invalid input
     * is provided. NB: this may change in the future to return 'null' in case
     * of invalid input...
     * <p/>
     * In order to be valid, it needs to contain Base64 data:
     * <p/>
     * particularly:
     * <p/>
     * * the provided String's length is a multiple of 4.
     * * the provided String must contain only Base64 characters:
     * A???Z, a???z, and 0???9, + and /
     * * the = is only used for padding and may only occur at the end
     * of input.
     * <p/>
     * For convienience, whitespace (" ", "\t", "\r", "\n") is removed
     * from the input.
     */
    public static byte[] decode(String base64) {
        char[] b64 = normalizeString(base64).toCharArray();
        if (0 != (b64.length % 4)) {
            throw new IllegalArgumentException(
                    "invalid b64 string length, must be multiple of 4: " + normalizeString(base64)
            );
        }
        int len = 3 * (b64.length / 4);
        byte[] enc = new byte[len];
        for (int i = 0; i != b64.length; i += 4) {
            decodeFour(b64, i, enc);
        }
        if (b64.length > 0 && '=' == b64[b64.length - 1]) {
            --len;
            if (b64.length > 1 && '=' == b64[b64.length - 2]) {
                --len;
            }
        }
        byte[] ret = new byte[len];
        System.arraycopy(enc, 0, ret, 0, len);
        return ret;
    }

    /**
     * Lookup table for encoding
     */
    private static final char[] BASE64 = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    };

    /**
     * Lookup table for decoding
     */
    private static final byte[] ESAB64 = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    /*                                                      = (padding) */
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 0, -1, -1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };


    private static void decodeFour(char[] b64, int i, byte[] ret) {
        byte b1 = getByte(b64[i]);
        byte b2 = getByte(b64[i + 1]);
        byte b3 = getByte(b64[i + 2]);
        byte b4 = getByte(b64[i + 3]);


        int location = 3 * (i / 4);

        ret[location] = (byte) ((b1 << 2) | (b2 >> 4));

        ret[location + 1] = (byte) (((b2 & 0x0f) << 4) | (b3 >> 2));
        ret[location + 2] = (byte) (((b3 & 0x03) << 6) | (b4));

    }

    private static byte getByte(char c) {
        if (c > ESAB64.length) {
            throw new IllegalArgumentException("Not a valid base64 char:" + Character.toString(c));
        }
        if (-1 == ESAB64[c]) {

            throw new IllegalArgumentException("Not a valid base64 char:" + Character.toString(c));
        }
        return ESAB64[c];
    }

    private static String normalizeString(String base64) {
        String ret = base64.trim();
        ret = ret.replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "");

        int idx = ret.indexOf("=");
        if (-1 != idx) {
            if (idx < ret.length() - 2) {
                throw new IllegalArgumentException("Equal (=) in the middle of a String:" + ret);
            } else if (idx != ret.length() - 1) {
                if ('=' != ret.charAt(ret.length() - 1)) {
                    throw new IllegalArgumentException("Equal (=) in the middle of a String:" + ret);
                }
            }
        }
        return ret;
    }

    static void lookup1(StringBuilder buf, byte[] bytes, int index) {
        int lu1 = uint(bytes[index]);

        buf.append(BASE64[lu1 >>> 2]);
        buf.append(BASE64[(lu1 & 0x03) << 4]);

        buf.append("==");
    }

    static void lookup2(StringBuilder buf, byte[] bytes, int index) {
        int u1, u2;
        u1 = uint(bytes[index]);
        u2 = uint(bytes[index + 1]);

        int l1 = u1 >>> 2;
        int l2 = (u1 & 0x03) << 4;
        l2 |= ((u2 & 0xf0) >>> 4);
        int l3 = (u2 & 0x0f) << 2;

        buf.append(BASE64[l1]);
        buf.append(BASE64[l2]);
        buf.append(BASE64[l3]);
        buf.append('=');
    }

    static void lookup3(StringBuilder buf, byte[] bytes, int index) {
        int u1, u2, u3;
        u1 = uint(bytes[index]);
        u2 = uint(bytes[index + 1]);
        u3 = uint(bytes[index + 2]);
        int l1 = u1 >>> 2;
        int l2 = (u1 & 0x03) << 4;
        l2 |= ((u2 & 0xf0) >>> 4);
        int l3 = (u2 & 0x0f) << 2;
        l3 |= ((u3 & 0xc0) >>> 6);
        int l4 = u3 & 0x3f;


        buf.append(BASE64[l1]);
        buf.append(BASE64[l2]);
        buf.append(BASE64[l3]);
        buf.append(BASE64[l4]);
    }

    static int uint(byte b) {
        return b & 0xff;
    }
    // public byte[] decode(String base64) {}

    static void test() {
        check("bGVhc3VyZS4=".equals(Base64.encode("leasure.".getBytes())));
        check("ZWFzdXJlLg==".equals(Base64.encode("easure.".getBytes())));
        check("YXN1cmUu".equals(Base64.encode("asure.".getBytes())));
        check("c3VyZS4=".equals(Base64.encode("sure.".getBytes())));
        check("TWFu".equals(Base64.encode("Man".getBytes())));
        check("".equals(Base64.encode("".getBytes())));
        check("Zg==".equals(Base64.encode("f".getBytes())));
        check("Zm8=".equals(Base64.encode("fo".getBytes())));
        check("Zm9v".equals(Base64.encode("foo".getBytes())));
        check("Zm9vYg==".equals(Base64.encode("foob".getBytes())));
        check("Zm9vYmE=".equals(Base64.encode("fooba".getBytes())));
        check("Zm9vYmFy".equals(Base64.encode("foobar".getBytes())));

        byte[] neg = {0, -1, -2, -3, -4};
        check("AP/+/fw=".equals(Base64.encode(neg)));
        //p(new String(neg));


    }

    static void test2() {
        check(arraycmp("leasure.".getBytes(), Base64.decode("bGVhc3VyZS4=")));
        check(arraycmp("easure.".getBytes(), Base64.decode("ZWFzdXJlLg==")));
        check(arraycmp("asure.".getBytes(), Base64.decode("YXN1cmUu")));
        check(arraycmp("sure.".getBytes(), Base64.decode("c3VyZS4=")));
        check(arraycmp("".getBytes(), Base64.decode("")));
        check(arraycmp("foobar".getBytes(), Base64.decode("Zm9vYmFy")));
        check(arraycmp("fooba".getBytes(), Base64.decode("Zm9vYmE=")));
        check(arraycmp("foob".getBytes(), Base64.decode("Zm9vYg==")));
        check(arraycmp("foo".getBytes(), Base64.decode("Zm9v")));
        check(arraycmp("fo".getBytes(), Base64.decode("Zm8=")));
        check(arraycmp("f".getBytes(), Base64.decode("Zg==")));
        byte[] neg = {0, -1, -2, -3, -4};
        check(arraycmp(neg, Base64.decode("AP/+/fw=")));

        //parr("leasure.".getBytes());
        //parr(Base64.decode("bGVhc3VyZS4="));

    }

    static boolean arraycmp(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) {
            return false;
        }
        for (int i = 0; i != b1.length; ++i) {
            if (b1[i] != b2[i]) {
                return false;
            }
        }
        return true;
    }


    static void createLookup() {
        int[] bytes = new int[256];
        for (int i = 0; i != bytes.length; ++i) {
            bytes[i] = -1;
        }
        for (int i = 0; i != BASE64.length; ++i) {
            bytes[BASE64[i]] = i;
        }
        for (int i : bytes) {
            p(i);
        }
    }

    static void check(boolean passed) {
        if (!passed) {
            throw new RuntimeException("Test failed!");
        }
    }

    static void p(Object o) {
        System.out.println(o);
    }

    static void parr(byte[] arr) {
        for (int i = 0; i != arr.length; ++i) {
            p("" + i + ":" + arr[i]);
        }
    }

    public static void main(String[] args) {
        System.out.println("running tests...");
        test();
        //createLookup();
        test2();
    }

}


