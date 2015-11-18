package com.presseverykey.u2f.example;

import com.presseverykey.u2f.Device;
import de.kuriositaet.util.crypto.KeyPair;

import static de.kuriositaet.util.crypto.Random.random;

/**
 * Created by a2800276 on 2015-10-30.
 */
public abstract class SimpleDevice extends Device {
    @Override
    protected boolean testUserPresence() {
        return true;
    }

    @Override
    protected java.security.KeyPair generateP256KeyPair() {
        KeyPair pair = KeyPair.generateKeyPair(KeyPair.Algorithm.P256);
        return pair.getJCAKeyPair();
    }

    @Override
    protected byte[] generateKeyHandle(java.security.KeyPair pair) {
        return random(32);
    }
}
