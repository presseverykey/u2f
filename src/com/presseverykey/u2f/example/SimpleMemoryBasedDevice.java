package com.presseverykey.u2f.example;

import com.presseverykey.u2f.Device;
import com.presseverykey.u2f.U2F;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;

import static com.presseverykey.u2f.Util.*;

/**
 * Created by a2800276 on 2015-10-30.
 */
public class SimpleMemoryBasedDevice extends SimpleDevice {

    private final HashMap<String, Entry> registrations;

    public SimpleMemoryBasedDevice() {
        this.registrations = new HashMap<String, Entry>();
    }

    class Entry {
        PrivateKey pk;
        long counter;

        Entry(PrivateKey pk) {
            this.pk = pk;
        }
    }

    private static final String ATTESTATION_PK = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAR/D0p5/ZW3Kp4uv9g06zXZ2s6lVGUgtV2FfaYZ5gFug==";

    @Override
    protected PrivateKey attestationPrivateKey() {
        try {
            byte[] pkBytes = Base64.decode(ATTESTATION_PK);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkBytes);
            return keyFactory.generatePrivate(keySpec);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static final String ATTESTATION_CERT_X509_B64 = "MIICBTCCAamgAwIBAgIEcHKfOzAMBggqhkjOPQQDAgUAMHcxCzAJBgNVBAYTAkRFMQwwCgYDVQQIEwNOUlcxDjAMBgNVBAcTBUtvZWxuMRswGQYDVQQKExJQcmVzcyBFdmVyeSBLZXkgVUcxGDAWBgNVBAsTD1RlY2huaWNhbCBTdGFmZjETMBEGA1UEAxMKVGltIEJlY2tlcjAeFw0xNTEwMjkyMjI5MjZaFw0xNjAxMjcyMjI5MjZaMHcxCzAJBgNVBAYTAkRFMQwwCgYDVQQIEwNOUlcxDjAMBgNVBAcTBUtvZWxuMRswGQYDVQQKExJQcmVzcyBFdmVyeSBLZXkgVUcxGDAWBgNVBAsTD1RlY2huaWNhbCBTdGFmZjETMBEGA1UEAxMKVGltIEJlY2tlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGwjwmlUzwcNi2Acpw8+VHl2xpJ8pwaQAqGV3hOBG94PryngxqVGXzRuq2vIiOqgeMGTVNhHm+4WvLD7ScclrnWjITAfMB0GA1UdDgQWBBRQRvI1usBfwqofbUxwtapBcF5rjzAMBggqhkjOPQQDAgUAA0gAMEUCIQCYygGTgIqRnCNXigPqOb+xDIZrfkTNU34yQAV/KOdXywIgVNg7hGvjQ1abSqtSf4IuCCz3bPp4jcvfCAmrey48wkc=";

    @Override
    protected byte[] attestationCertificateX509Bytes() {
        return Base64.decode(ATTESTATION_CERT_X509_B64);
    }

    @Override
    protected void storeKeyForApplicationAndHandle(KeyPair pair, byte[] applicationParameter, byte[] keyhandle) {
        this.registrations.put(alias(applicationParameter, keyhandle), new Entry(pair.getPrivate()));
    }

    @Override
    protected boolean hasKeyForApplicationAndHandle(U2F.AuthenticationRequestMessage req) {
        return this.registrations.containsKey(alias(req.getApplicationParameter(), req.getKeyHandle()));
    }

    @Override
    protected PrivateKey userPrivateKey(U2F.AuthenticationRequestMessage req) {
        String alias = alias(req);
        if (!this.registrations.containsKey(alias)) {
            throw new U2F.U2FNoKeyException();
        }
        Entry e = this.registrations.get(alias);
        return e.pk;
    }

    @Override
    protected long getCounter(byte[] applicationParameter, byte[] keyHandle) {
        String alias = alias(applicationParameter, keyHandle);
        if (!this.registrations.containsKey(alias)) {
            throw new U2F.U2FNoKeyException();
        }
        Entry e = this.registrations.get(alias);
        e.counter += 1;
        if (e.counter > 0xffffffffL) {
            e.counter = 0L;
        }
        return e.counter;
    }

    String alias(byte[] applicationParameter, byte[] keyHandle) {
        return bytes2Hex(sha256(applicationParameter, keyHandle));
    }

    String alias(U2F.AuthenticationRequestMessage req) {
        return alias(req.getApplicationParameter(), req.getKeyHandle());
    }

    public static void main(String[] args) {
        Device device = new SimpleMemoryBasedDevice();

        p("Device Registration");
        byte[] bytes = new byte[64];
        U2F.RegistrationRequestMessage req = new U2F.RegistrationRequestMessage(bytes);
        U2F.RegistrationResponseMessage resp = device.generateRegistrationResponse(req);
        System.out.println(resp);


        p("First Authentication");
        U2F.AuthenticationRequestMessage areq = new U2F.AuthenticationRequestMessage(
                random(32),
                req.getApplicationParameter(),
                resp.getKeyHandle()
        );
        U2F.AuthenticationResponseMessage aresp = device.generateAuthenticationResponse(areq);
        p(aresp);

        p("Second Authentication");
        areq = new U2F.AuthenticationRequestMessage(
                random(32),
                req.getApplicationParameter(),
                resp.getKeyHandle()
        );
        aresp = device.generateAuthenticationResponse(areq);
        p(aresp);
    }
}
