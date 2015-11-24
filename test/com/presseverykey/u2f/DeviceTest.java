package com.presseverykey.u2f;

import com.presseverykey.u2f.example.SimpleDevice;
import com.presseverykey.u2f.example.SimpleMemoryBasedDevice;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.PrivateKey;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static util.crypto.Random.random;

/**
 * Created by a2800276 on 2015-11-10.
 */
public class DeviceTest {
    /**
     * Base Dummy implementation for Device, so tests only need to override the methods they are acutally interested in.
     */
    class DeviceBase extends Device {

        @Override
        protected byte[] generateKeyHandle(KeyPair pair) {
            return new byte[0];
        }

        @Override
        protected PrivateKey attestationPrivateKey() {
            return null;
        }

        @Override
        protected byte[] attestationCertificateX509Bytes() {
            return new byte[0];
        }

        @Override
        protected void storeKeyForApplicationAndHandle(KeyPair pair, byte[] applicationParameter, byte[] keyhandle) {

        }

        @Override
        protected KeyPair generateP256KeyPair(U2F.RegistrationRequestMessage req) {
            return null;
        }

        @Override
        protected boolean hasKeyForApplicationAndHandle(U2F.AuthenticationRequestMessage req) {
            return false;
        }

        @Override
        protected PrivateKey userPrivateKey(U2F.AuthenticationRequestMessage req) throws U2F.U2FNoKeyException {
            return null;
        }

        @Override
        protected long getCounter(U2F.AuthenticationRequestMessage req) {
            return 0;
        }

        @Override
        protected boolean testUserPresence() {
            return false;
        }
    }

    static byte[] EMPTY = {};
    static byte[] ZERO = {0, 0, 0, 0};
    static byte[] F_ZERO_F = {(byte) 0xf0, 0, 0, 0x0f};
    static byte[] ONETWOETC = {1, 2, 3, 4};

    @Test
    public void testHandleAPDU() throws Exception {
        Device testDevice = new DeviceBase();
        APDU apdu = new APDU();
        apdu.cla = Constants.U2F_CLASS + 1;
        for (byte b = Byte.MIN_VALUE; ; ++b) {
            if (b == Constants.U2F_CLASS) {
                continue;
            }
            assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_COMMAND_NOT_ALLOWED);
            if (b == Byte.MAX_VALUE) {
                break;
            }
        }
        apdu.cla = Constants.U2F_CLASS;
        apdu.ins = (byte) 0xff;
        assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_INS_NOT_SUPPORTED);

        apdu.ins = Constants.U2F_REGISTER;
        assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_WRONG_DATA);

        byte[] THIRTY2 = random(32);
        U2F.AuthenticationRequestMessage req = new U2F.AuthenticationRequestMessage(THIRTY2, THIRTY2, THIRTY2);
        apdu.payload = req.toBytes();
        apdu.ins = Constants.U2F_AUTHENTICATE;
        apdu.p1 = Constants.U2F_AUTH_CHECK_ONLY;
        assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_WRONG_DATA);

        apdu.p1 = Constants.U2F_AUTH_ENFORCE;
        assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_CONDITIONS_NOT_SATISFIED);

        apdu.p1 = Constants.U2F_AUTH_CHECK_ONLY;
        for (byte b = Byte.MIN_VALUE; ; ++b) {
            if (b == 7 || b == 3) { // check-only, enforce-user-presence-and-sign
                continue;
            }
            apdu.p1 = b;
            assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_COMMAND_NOT_ALLOWED);
            if (b == Byte.MAX_VALUE) {
                break;
            }
        }


        apdu.ins = Constants.U2F_VERSION;
        apdu.p1 = 0;
        assertEquals(testDevice.handleAPDU(apdu.toBytes()), Constants.U2F_SW_WRONG_DATA); // no payload
        apdu.payload = EMPTY;
        assertEquals(testDevice.handleAPDU(apdu.toBytes()).length, Constants.U2F_VERSION_BYTES.length + 2);
    }

    @Test
    public void testGenerateRegistrationResponse() throws Exception {
        Device d = new SimpleDevice() {
            public U2F.RegistrationRequestMessage req;
            public KeyPair keypair;

            @Override
            protected KeyPair generateP256KeyPair(U2F.RegistrationRequestMessage req) {
                this.keypair = super.generateP256KeyPair(req);
                return this.keypair;
            }

            @Override
            public U2F.RegistrationResponseMessage generateRegistrationResponse(U2F.RegistrationRequestMessage req) {
                this.req = req;
                return super.generateRegistrationResponse(req);
            }

            @Override
            protected byte[] generateKeyHandle(KeyPair pair) {
                assertEquals(pair, this.keypair);
                return this.req.getChallengeParameter();
            }

            @Override
            protected PrivateKey attestationPrivateKey() {
                return this.keypair.getPrivate();
            }

            @Override
            protected byte[] attestationCertificateX509Bytes() {
                return new byte[0];
            }

            @Override
            protected void storeKeyForApplicationAndHandle(KeyPair pair, byte[] applicationParameter, byte[] keyhandle) {
                assertEquals(pair, this.keypair);
                assertEquals(applicationParameter, this.req.getApplicationParameter());
                assertEquals(keyhandle, this.req.getChallengeParameter());
            }

            @Override
            protected boolean hasKeyForApplicationAndHandle(U2F.AuthenticationRequestMessage req) {
                return false;
            }

            @Override
            protected PrivateKey userPrivateKey(U2F.AuthenticationRequestMessage req) {
                return null;
            }

            @Override
            protected long getCounter(U2F.AuthenticationRequestMessage req) {
                return 0;
            }
        };
        U2F.RegistrationRequestMessage req = new U2F.RegistrationRequestMessage(random(64));
        U2F.RegistrationResponseMessage resp = d.generateRegistrationResponse(req);
        assertEquals(resp.getKeyHandle(), req.getChallengeParameter());
    }

    @Test
    public void testGenerateAuthenticationResponse() throws Exception {
        final byte[] keyhandle_valid = random(64);
        final byte[] keyhandle_invalid = random(64);
        final byte[] keyhandle_user_presence = random(64);
        Device device = new SimpleDevice() {
            public U2F.AuthenticationRequestMessage req;

            @Override
            protected PrivateKey attestationPrivateKey() {
                return null;
            }

            @Override
            protected byte[] attestationCertificateX509Bytes() {
                return new byte[0];
            }

            @Override
            protected void storeKeyForApplicationAndHandle(KeyPair pair, byte[] applicationParameter, byte[] keyhandle) {

            }

            @Override
            protected boolean hasKeyForApplicationAndHandle(U2F.AuthenticationRequestMessage req) {
                assertEquals(req, this.req);
                if (req.getApplicationParameter() == keyhandle_valid &&
                        req.getKeyHandle() == keyhandle_valid) {
                    return true;
                }
                return req.getKeyHandle() == keyhandle_user_presence;
            }

            @Override
            protected PrivateKey userPrivateKey(U2F.AuthenticationRequestMessage req) {
                assertEquals(req, this.req);
                if (req.getKeyHandle() == keyhandle_valid || req.getKeyHandle() == keyhandle_user_presence) {
                    //make one up.
                    return this.generateP256KeyPair(null).getPrivate();
                }
                return null;
            }

            @Override
            protected long getCounter(U2F.AuthenticationRequestMessage req) {
                assertEquals(req, this.req);
                return 0;
            }

            @Override
            public U2F.AuthenticationResponseMessage generateAuthenticationResponse(U2F.AuthenticationRequestMessage req) throws U2F.U2FNoKeyException, U2F.U2FUserPresenceException {
                this.req = req;
                return super.generateAuthenticationResponse(req);
            }

            @Override
            protected boolean testUserPresence() {
                if (this.req.getKeyHandle() == keyhandle_user_presence) {
                    return false;
                }
                return super.testUserPresence();
            }
        };

        U2F.AuthenticationRequestMessage req = new U2F.AuthenticationRequestMessage(keyhandle_valid, keyhandle_valid, keyhandle_valid);
        U2F.AuthenticationResponseMessage resp = device.generateAuthenticationResponse(req);
        assertEquals(resp.counter, ZERO);

        req = new U2F.AuthenticationRequestMessage(keyhandle_invalid, keyhandle_invalid, keyhandle_invalid);
        boolean caught = false;
        try {
            device.generateAuthenticationResponse(req);
        } catch (U2F.U2FNoKeyException t) {
            caught = true;
        }
        assertTrue(caught);
        caught = false;

        req = new U2F.AuthenticationRequestMessage(keyhandle_user_presence, keyhandle_user_presence, keyhandle_user_presence);
        try {
            device.generateAuthenticationResponse(req);
        } catch (U2F.U2FUserPresenceException t) {
            caught = true;
        }
        assertTrue(caught);
    }

    @Test
    public void testGetCounterBytes() throws Exception {
        class Wrap {
            long counter;
        }
        final Wrap counter = new Wrap();
        Device d = new SimpleMemoryBasedDevice() {
            @Override
            protected long getCounter(U2F.AuthenticationRequestMessage r) {
                return counter.counter;
            }
        };
        counter.counter = 0L;
        assertEquals(d.getCounterBytes(null), ZERO);
        counter.counter = 0x01020304;
        assertEquals(d.getCounterBytes(null), ONETWOETC);
        counter.counter = 0xf000000fL;
        assertEquals(d.getCounterBytes(null), F_ZERO_F);
        counter.counter = Long.MAX_VALUE;
        try {
            d.getCounterBytes(null);
        } catch (Throwable t) {
            assertEquals(t.getClass(), IllegalArgumentException.class);
        }
        counter.counter = Long.MIN_VALUE;
        try {
            d.getCounterBytes(null);
        } catch (Throwable t) {
            assertEquals(t.getClass(), IllegalArgumentException.class);
        }

    }


}