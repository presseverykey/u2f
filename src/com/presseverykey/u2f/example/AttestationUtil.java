package com.presseverykey.u2f.example;

import java.security.KeyStore;
import java.security.cert.Certificate;

import static com.presseverykey.u2f.Util.closeInputStream;

/**
 * Created by a2800276 on 2015-10-30.
 */
public class AttestationUtil {

    private static KeyStore loadKeyStore(String fn, String pw) {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            java.io.FileInputStream fis = null;
            try {
                fis = new java.io.FileInputStream(fn);
                ks.load(fis, pw.toCharArray());
            } finally {
                closeInputStream(fis);
            }
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        return ks;
    }

    public static void main(String[] args) throws Throwable {
        KeyStore ks = loadKeyStore("tim.keystore", "1234567890");
        Certificate cert = ks.getCertificate("attestation");
        p(Base64.encode(cert.getEncoded()));
        KeyStore.PasswordProtection p = new KeyStore.PasswordProtection("1234567890".toCharArray());
        KeyStore.PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry) ks.getEntry("attestation", p);
        p(Base64.encode(pke.getPrivateKey().getEncoded()));
    }

    private static void p(Object o) {
        System.out.println(o);
    }
}
