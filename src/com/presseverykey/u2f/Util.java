package com.presseverykey.u2f;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class Util {
    final protected static byte[] hex = "0123456789ABCDEF".getBytes();

    public static String bytes2Hex(byte[] bytes) {
        return bytes2Hex(bytes, 0, bytes.length);
    }

    public static String bytes2Hex(byte[] bytes, int offset, int count) {
        byte[] hexBytes = new byte[count * 2];
        for (int j = 0; j < count; j++) {
            int v = bytes[j + offset] & 0xFF;
            hexBytes[j * 2] = hex[v >>> 4];
            hexBytes[j * 2 + 1] = hex[v & 0x0F];
        }
        return new String(hexBytes);
    }

    public static byte[] sha256(byte[]... input) {
        byte[] digest = new byte[0];
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] bytes : input) {
                md.update(bytes);
            }
            digest = md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return digest;
    }

    static SecureRandom secureRandom = new SecureRandom();

    public static byte[] random(int count) {
        byte[] bytes = new byte[count];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static byte[] sign(PrivateKey priv, byte[]... data) {
        Signature ecdsa;
        try {
            ecdsa = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            ecdsa.initSign(priv);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        try {
            for (byte[] bytes : data) {
                ecdsa.update(bytes);
            }
            return ecdsa.sign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static void closeInputStream(InputStream is) {
        if (null != is) {
            try {
                is.close();
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
        }
    }

    public static void closeOutputStream(OutputStream os) {
        if (null != os) {
            try {
                os.close();
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
        }
    }

    public static void p(Object o) {
        System.out.println(o);
    }

    public static void p(Object[] os) {
        for (Object o : os) {
            p(o);
        }
    }
}
