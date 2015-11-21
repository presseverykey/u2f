package com.presseverykey.u2f;


import de.kuriositaet.util.crypto.Hash;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;


/**
 * Created by a2800276 on 2015-10-29.
 */
public abstract class Device {
    /**
     * Respond to an APDU as described in:
     * https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html
     *
     * @param apduBytes
     * @return response APDU
     */
    public byte[] handleAPDU(byte[] apduBytes) {
        return handleAPDU(APDU.scan(apduBytes));
    }

    public byte[] handleAPDU(APDU apdu) {
        switch (apdu.cla) {
            case Constants.U2F_CLASS:
                break;
            default:
                return Constants.U2F_SW_COMMAND_NOT_ALLOWED;
        }
        switch (apdu.ins) {
            case Constants.U2F_REGISTER:
                return handleU2FRegister(apdu);
            case Constants.U2F_AUTHENTICATE:
                return handleU2FAuthenticate(apdu);
            case Constants.U2F_VERSION:
                return handleU2FVersion(apdu);
            default:
                return Constants.U2F_SW_INS_NOT_SUPPORTED;

        }
    }

    /**
     * respond to the U2F Version command.
     *
     * @param apdu
     * @return response APDU
     */
    private byte[] handleU2FVersion(APDU apdu) {
        if (apdu.p1 != 0x00 || apdu.p2 != 0x00) {
            return Constants.U2F_SW_COMMAND_NOT_ALLOWED;
        }
        if (apdu.length != 0) {
            return Constants.U2F_SW_WRONG_DATA;
        }
        return apduResponse(Constants.U2F_VERSION_BYTES, Constants.U2F_SW_NO_ERROR);
    }

    /**
     * respond to the U2F Register command APDU.
     *
     * @param apdu
     * @return response APDU
     */
    private byte[] handleU2FRegister(APDU apdu) {
        if (apdu.p1 != 0x00 || apdu.p2 != 0x00) {
            return Constants.U2F_SW_COMMAND_NOT_ALLOWED;
        }
        if (apdu.payload.length != 64) {
            return Constants.U2F_SW_WRONG_DATA;
        }
        if (!testUserPresence()) {
            return Constants.U2F_SW_CONDITIONS_NOT_SATISFIED;
        }
        U2F.RegistrationRequestMessage req = new U2F.RegistrationRequestMessage(apdu.payload);
        U2F.RegistrationResponseMessage resp = generateRegistrationResponse(req);
        return apduResponse(resp.toBytes(), Constants.U2F_SW_NO_ERROR);
    }

    public synchronized U2F.RegistrationResponseMessage generateRegistrationResponse(U2F.RegistrationRequestMessage req) {
        KeyPair pair = generateP256KeyPair(req);
        byte[] keyhandle = generateKeyHandle(pair);
        storeKeyForApplicationAndHandle(pair, req.getApplicationParameter(), keyhandle);
        U2F.RegistrationResponseMessage response = new U2F.RegistrationResponseMessage();

        //response.setUserPK(pair.getPublic().getEncoded());
        de.kuriositaet.util.crypto.KeyPair.ECPublicKey publicKey =
                new de.kuriositaet.util.crypto.KeyPair.ECPublicKey((ECPublicKey) pair.getPublic());
        response.setUserPK(publicKey.toUncompressedCurvePoint());
        response.setKeyHandle(keyhandle);
        response.setAttestationCert(attestationCertificateX509Bytes());

        byte[] signData = signatureDataRegistration(
                req.getApplicationParameter(),
                req.getChallengeParameter(),
                keyhandle,
                response.getUserPK()
        );
        de.kuriositaet.util.crypto.KeyPair.PrivateKey privateKey =
                new de.kuriositaet.util.crypto.KeyPair.PrivateKey(attestationPrivateKey());

        response.setSignature(privateKey.sign(Hash.Algorithm.SHA256, signData));

        return response;
    }

    /**
     * Utility to assemble the data contained in the Registration Response signature.
     * @param applicationParameter
     * @param challengeParameter
     * @param keyhandle
     * @param userPK
     * @return
     */
    private byte[] signatureDataRegistration(
            byte[] applicationParameter,
            byte[] challengeParameter,
            byte[] keyhandle,
            byte[] userPK
    ) {
        int len = 1 + 32 + 32 + keyhandle.length + userPK.length;
        byte[] bytes = new byte[len];
        int pos = 0;
        bytes[pos++] = 0;
        System.arraycopy(applicationParameter, 0, bytes, pos, 32);
        pos += 32;
        System.arraycopy(challengeParameter, 0, bytes, pos, 32);
        pos += 32;
        System.arraycopy(keyhandle, 0, bytes, pos, keyhandle.length);
        pos += keyhandle.length;
        System.arraycopy(userPK, 0, bytes, pos, userPK.length);
        return bytes;
    }

    /**
     * In case the concrete implementation wraps the PK in the keyhandle (see
     * Fido Raw Messages §4.3) this method may be implemented to generate the
     * wrapped value to use as keyhandle. Otherwise, the keyHandle is an opaque
     * byte value used as a lookup.
     *
     * @param pair
     * @return
     */
    protected abstract byte[] generateKeyHandle(KeyPair pair);

    /**
     * Return the private key used to sign Registration Responses.
     *
     * @return the private key of the attestation key.
     */
    protected abstract PrivateKey attestationPrivateKey();

    /**
     * Return the X509 representation of the Attestation Certificate used
     * in RegistrationResponse messages.
     *
     * @return x509 bytes.
     */
    protected abstract byte[] attestationCertificateX509Bytes();

    /**
     * Associate the user key pair with the application and keyhandle parameters and persist the key.
     * In case this is a wrapped key (key wrapped within the keyhandle) this may
     * not be necessary to save the key, depending on implementation, it may still be useful to take note of the
     * association.
     *
     * @param pair
     * @param applicationParameter
     * @param keyhandle
     */

    protected abstract void storeKeyForApplicationAndHandle(KeyPair pair, byte[] applicationParameter, byte[] keyhandle);

    /**
     * Generate a P-256 Keypair. Assume this keypair will be used as the user key.
     *
     * @return
     * @param req
     */
    protected abstract KeyPair generateP256KeyPair(U2F.RegistrationRequestMessage req);


    /**
     * Handles Authentication Command.
     * @param apdu
     * @return response APDU
     */
    private byte[] handleU2FAuthenticate(APDU apdu) {
        if (apdu.p2 != 0x00) {
            return Constants.U2F_SW_COMMAND_NOT_ALLOWED;
        }
        U2F.AuthenticationRequestMessage req = new U2F.AuthenticationRequestMessage(apdu.payload);
        switch (apdu.p1) {
            case Constants.U2F_AUTH_CHECK_ONLY:
                if (hasKeyForApplicationAndHandle(req)) {
                    return Constants.U2F_SW_CONDITIONS_NOT_SATISFIED;
                } else {
                    return Constants.U2F_SW_WRONG_DATA;
                }
            case Constants.U2F_AUTH_ENFORCE:
                if (!testUserPresence()) {
                    return Constants.U2F_SW_CONDITIONS_NOT_SATISFIED;
                }
                if (!hasKeyForApplicationAndHandle(req)) {
                    return Constants.U2F_SW_WRONG_DATA;
                }
                U2F.AuthenticationResponseMessage resp = generateAuthenticationResponse(req);
                return apduResponse(resp.toBytes(), Constants.U2F_SW_NO_ERROR);
            default:
                return Constants.U2F_SW_COMMAND_NOT_ALLOWED;
        }
    }

    /**
     * check whether this device has a key for the indicated application parameter and keyHandle available.
     */
    protected abstract boolean hasKeyForApplicationAndHandle(U2F.AuthenticationRequestMessage req);

    public synchronized U2F.AuthenticationResponseMessage generateAuthenticationResponse(U2F.AuthenticationRequestMessage req)
            throws U2F.U2FNoKeyException, U2F.U2FUserPresenceException {
        if (!hasKeyForApplicationAndHandle(req)) {
            throw new U2F.U2FNoKeyException();
        }
        if (!testUserPresence()) {
            throw new U2F.U2FUserPresenceException();
        }

        U2F.AuthenticationResponseMessage resp = new U2F.AuthenticationResponseMessage();
        resp.userPresence = 0x01;
        resp.counter = getCounterBytes(req);

        byte[] signatureData = signatureDataAuthentication(
                req.getApplicationParameter(),
                resp.userPresence,
                resp.counter,
                req.getChallengeParameter()
        );


        if (userPrivateKey(req) == null) {
            throw new U2F.U2FNoKeyException();
        }

        de.kuriositaet.util.crypto.KeyPair.PrivateKey privateKey = new
                de.kuriositaet.util.crypto.KeyPair.PrivateKey(userPrivateKey(req));

        resp.signature = privateKey.sign(Hash.Algorithm.SHA256, signatureData);

        return resp;
    }

    protected byte[] getCounterBytes(U2F.AuthenticationRequestMessage req) {

        long counter = getCounter(req);

        if (counter > 0xffffffffL || counter < 0) {
            throw new IllegalArgumentException("counter value too large or negative");
        }

        byte[] bytes = new byte[4];
        bytes[0] = (byte) (counter >> 24);
        bytes[1] = (byte) ((counter >> 16) & 0xff);
        bytes[2] = (byte) ((counter >> 8) & 0xff);
        bytes[3] = (byte) (counter & 0xff);

        return bytes;
    }

    /**
     * Retrieve the private key generated for the provided keyhandle and application parameter.
     *
     * @param req
     * @return
     * @throws U2F.U2FNoKeyException
     */
    protected abstract PrivateKey userPrivateKey(U2F.AuthenticationRequestMessage req) throws U2F.U2FNoKeyException;

    private byte[] signatureDataAuthentication(
            byte[] applicationParameter,
            byte userPresence,
            byte[] counter,
            byte[] challengeParameter
    ) {
        int len = 32 + 1 + 4 + 32;
        byte[] bytes = new byte[len];
        int pos = 0;
        System.arraycopy(applicationParameter, 0, bytes, pos, 32);
        pos += 32;
        bytes[pos++] = userPresence;
        System.arraycopy(counter, 0, bytes, pos, 4);
        pos += 4;
        System.arraycopy(challengeParameter, 0, bytes, pos, 32);
        return bytes;
    }

    /**
     * get the current (incremented) counter for the keyhandle and application parameter
     **/
    protected abstract long getCounter(U2F.AuthenticationRequestMessage req);


    /**
     * Implement this to test for user presence,
     * if the device does not require user presence testing, implment to return true.
     *
     * @return true if user presence was determined
     */
    protected abstract boolean testUserPresence();


    private static byte[] apduResponse(byte[] data, byte[] sw12) {
        if (sw12.length != 2) {
            throw new APDU.APDUException("incorret sw12 length");
        }
        byte[] resp = new byte[data.length + 2];
        System.arraycopy(data, 0, resp, 0, data.length);
        System.arraycopy(sw12, 0, resp, data.length, 2);
        return resp;
    }


}
