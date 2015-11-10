package com.presseverykey.u2f.example;

import com.presseverykey.u2f.U2F;
import com.presseverykey.u2f.Util;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;

import static com.presseverykey.u2f.Util.p;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class SimpleKeystoreDevice extends SimpleDevice {
    private final KeyStore keystore;
    private final String keystoreFn;
    private final char[] keystorePw;
    private final String counterFn;
    private final HashMap<String, Long> counters;


    public SimpleKeystoreDevice(String keystoreFn, String keyStorePw, String counterFn) {
        this.keystoreFn = keystoreFn;
        this.keystorePw = keyStorePw.toCharArray();
        this.counterFn = counterFn;

        this.keystore = loadKeyStore();
        this.counters = loadCounters();
    }

    private HashMap<String, Long> loadCounters() {
        File file = new File(this.counterFn);
        if (!file.exists()) {
            return new HashMap<>();
        }

        ObjectInputStream ois = null;
        HashMap<String, Long> map;
        try {
            FileInputStream fis = new FileInputStream(counterFn);
            ois = new ObjectInputStream(fis);
            map = (HashMap<String, Long>) ois.readObject();
        } catch (Throwable t) {
            throw new RuntimeException(t);
        } finally {
            Util.closeInputStream(ois);
        }

        return map;
    }

    private void saveCounters() {
        ObjectOutputStream oos = null;
        try {
            FileOutputStream fos = new FileOutputStream(this.counterFn);
            oos = new ObjectOutputStream(fos);
            oos.writeObject(this.counters);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            Util.closeOutputStream(oos);
        }

    }

    private KeyStore loadKeyStore() {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            java.io.FileInputStream fis = null;
            try {
                fis = new java.io.FileInputStream(this.keystoreFn);
                ks.load(fis, this.keystorePw);
            } finally {
                Util.closeInputStream(fis);
            }
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        return ks;
    }

    private void saveKeystore() {
        // store away the keystore
        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream(this.keystoreFn);
            keystore.store(fos, this.keystorePw);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        } finally {
            Util.closeOutputStream(fos);
        }
    }

    @Override
    protected void storeKeyForApplicationAndHandle(KeyPair pair, byte[] applicationParameter, byte[] keyhandle) {
        String alias = keyStoreAlias(applicationParameter, keyhandle);
        Certificate[] bogusChain = new Certificate[1];
        bogusChain[0] = attestationCertificate();
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(pair.getPrivate(), bogusChain);
        KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection("1234567890".toCharArray());
        try {
            keystore.setEntry(alias, entry, prot);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        this.counters.put(alias, 0L);

        saveCounters();
        saveKeystore();
    }

    @Override
    protected boolean hasKeyForApplicationAndHandle(U2F.AuthenticationRequestMessage req) {
        String alias = keyStoreAlias(req.getApplicationParameter(), req.getKeyHandle());
        try {
            return this.keystore.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected PrivateKey userPrivateKey(U2F.AuthenticationRequestMessage req) {
        String alias = keyStoreAlias(req.getApplicationParameter(), req.getKeyHandle());
        return getPK(alias);
    }

    private PrivateKey getPK(String alias) {
        KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection("1234567890".toCharArray());

        try {
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) this.keystore.getEntry(alias, prot);
            return entry.getPrivateKey();
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected long getCounter(byte[] applicationParameter, byte[] keyHandle) {
        String alias = keyStoreAlias(applicationParameter, keyHandle);
        if (!this.counters.containsKey(alias)) {
            // this is a RuntimeException and not
            // a NoKeyException because the fact we ended up here indicates
            // KeyStore and Counter storage are out of sync.
            throw new RuntimeException("no counter for: " + alias);
        }
        Long counter = this.counters.get(alias);
        counter += 1;
        if (counter > 0xffffffffL) {
            counter = 0L;
        }
        this.counters.put(alias, counter);
        saveCounters();

        return counter;
    }


    String keyStoreAlias(byte[] applicationParameter, byte[] keyHandle) {
        byte[] alias_bytes = Util.sha256(applicationParameter, keyHandle);
        return Util.bytes2Hex(alias_bytes);
    }

    Certificate attestationCertificate() {
        try {
            return this.keystore.getCertificate("attestation");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected byte[] attestationCertificateX509Bytes() {
        try {
            return attestationCertificate().getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }


    protected PrivateKey attestationPrivateKey() {
        return getPK("attestation");
    }

    public static void main(String[] args) throws Throwable {

        String ks_fn = "tim.keystore";
        String ks_pw = "1234567890";
        String cnt_fn = "tim.counters";
        SimpleKeystoreDevice device = new SimpleKeystoreDevice(ks_fn, ks_pw, cnt_fn);

        Util.p("Device Registration");
        byte[] bytes = new byte[64];
        U2F.RegistrationRequestMessage req = new U2F.RegistrationRequestMessage(bytes);
        U2F.RegistrationResponseMessage resp = device.generateRegistrationResponse(req);
        System.out.println(resp);


        Util.p("First Authentication");
        U2F.AuthenticationRequestMessage areq = new U2F.AuthenticationRequestMessage(
                Util.random(32),
                req.getApplicationParameter(),
                resp.getKeyHandle()
        );
        U2F.AuthenticationResponseMessage aresp = device.generateAuthenticationResponse(areq);
        p(aresp);

        Util.p("Second Authentication");
        areq = new U2F.AuthenticationRequestMessage(
                Util.random(32),
                req.getApplicationParameter(),
                resp.getKeyHandle()
        );
        aresp = device.generateAuthenticationResponse(areq);
        p(aresp);


    }

}
