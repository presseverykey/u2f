package com.presseverykey.u2f.example;

import com.presseverykey.u2f.Device;
import com.presseverykey.u2f.Util;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by a2800276 on 2015-10-30.
 */
public abstract class SimpleDevice extends Device {
    @Override
    protected boolean testUserPresence() {
        return true;
    }

    @Override
    protected KeyPair generateKeyPair() {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        try {
            generator.initialize(spec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        return generator.generateKeyPair();
    }

    @Override
    protected byte[] generateKeyHandle(KeyPair pair) {
        return Util.random(32);
    }
}
