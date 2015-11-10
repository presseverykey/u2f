package com.presseverykey.u2f;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class U2F {
    public static class RegistrationRequestMessage {
        public RegistrationRequestMessage(byte[] bytes) {
            if (bytes.length != 64) {
                throw new U2FException("incorrect length");
            }
            setChallengeParameter(new byte[32]);
            setApplicationParameter(new byte[32]);

            System.arraycopy(bytes, 0, getChallengeParameter(), 0, 32);
            System.arraycopy(bytes, 32, getApplicationParameter(), 0, 32);

        }

        private byte[] challengeParameter;
        private byte[] applicationParameter;

        public byte[] getChallengeParameter() {
            return challengeParameter;
        }

        public void setChallengeParameter(byte[] challengeParameter) {
            this.challengeParameter = challengeParameter;
        }

        public byte[] getApplicationParameter() {
            return applicationParameter;
        }

        public void setApplicationParameter(byte[] applicationParameter) {
            this.applicationParameter = applicationParameter;
        }
    }

    public static class AuthenticationRequestMessage {
        private byte[] challengeParameter;
        private byte[] applicationParameter;
        private byte[] keyHandle;

        public AuthenticationRequestMessage(byte[] bytes) {
            if (bytes.length < 65 || bytes.length != 65 + bytes[64]) {
                throw new U2FException("incorrect length");
            }
            setChallengeParameter(new byte[32]);
            setApplicationParameter(new byte[32]);
            setKeyHandle(new byte[bytes[64]]);

            System.arraycopy(bytes, 0, getChallengeParameter(), 0, 32);
            System.arraycopy(bytes, 32, getApplicationParameter(), 0, 32);
            System.arraycopy(bytes, 65, getKeyHandle(), 0, bytes[64]);
        }

        public AuthenticationRequestMessage(byte[] challengeParameter, byte[] applicationParameter, byte[] keyHandle) {
            this.setChallengeParameter(challengeParameter);
            this.setApplicationParameter(applicationParameter);
            this.setKeyHandle(keyHandle);
        }

        public byte[] getChallengeParameter() {
            return challengeParameter;
        }

        public void setChallengeParameter(byte[] challengeParameter) {
            this.challengeParameter = challengeParameter;
        }

        public byte[] getApplicationParameter() {
            return applicationParameter;
        }

        public void setApplicationParameter(byte[] applicationParameter) {
            this.applicationParameter = applicationParameter;
        }

        public byte[] getKeyHandle() {
            return keyHandle;
        }

        public void setKeyHandle(byte[] keyHandle) {
            this.keyHandle = keyHandle;
        }
    }

    public static class RegistrationResponseMessage {
        private byte[] userPK;
        private byte[] keyHandle;
        private byte[] attestationCert;
        private byte[] signature;

        public byte[] toBytes() {
            int len = 1 + 65 + 1 + getKeyHandle().length + getAttestationCert().length + getSignature().length;
            int pos = 0;
            byte[] bytes = new byte[len];
            bytes[pos] = 0x05;
            pos += 1;
            System.arraycopy(getUserPK(), 0, bytes, pos, 65);
            pos += 65;
            bytes[pos] = (byte) getKeyHandle().length;
            pos += 1;
            System.arraycopy(getKeyHandle(), 0, bytes, pos, getKeyHandle().length);
            pos += getKeyHandle().length;
            System.arraycopy(getAttestationCert(), 0, bytes, pos, getAttestationCert().length);
            pos += getAttestationCert().length;
            System.arraycopy(getSignature(), 0, bytes, pos, getSignature().length);
            return bytes;
        }

        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("userPK:");
            builder.append(Util.bytes2Hex(getUserPK()));
            builder.append("\n");
            builder.append("keyHandle:");
            builder.append(Util.bytes2Hex(getKeyHandle()));
            builder.append("\n");
            builder.append("attestationCert:");
            builder.append(Util.bytes2Hex(getAttestationCert()));
            builder.append("\n");
            builder.append("signature:");
            builder.append(Util.bytes2Hex(getSignature()));
            builder.append("\n");
            return builder.toString();
        }

        public byte[] getUserPK() {
            return userPK;
        }

        public void setUserPK(byte[] userPK) {
            this.userPK = userPK;
        }

        public byte[] getKeyHandle() {
            return keyHandle;
        }

        public void setKeyHandle(byte[] keyHandle) {
            this.keyHandle = keyHandle;
        }

        public byte[] getAttestationCert() {
            return attestationCert;
        }

        public void setAttestationCert(byte[] attestationCert) {
            this.attestationCert = attestationCert;
        }

        public byte[] getSignature() {
            return signature;
        }

        public void setSignature(byte[] signature) {
            this.signature = signature;
        }
    }

    public static class AuthenticationResponseMessage {
        byte userPresence;
        byte[] counter;
        byte[] signature;

        public byte[] toBytes() {
            int len = 1 + 4 + 32;
            byte[] bytes = new byte[len];
            bytes[0] = userPresence;
            System.arraycopy(counter, 0, bytes, 1, 4);
            System.arraycopy(signature, 0, bytes, 5, signature.length);
            return bytes;
        }

        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("userPresence: ");
            builder.append(userPresence);
            builder.append("\n");
            builder.append("counter: " + Util.bytes2Hex(counter) + "\n");
            builder.append("signature: " + Util.bytes2Hex(signature) + "\n");
            return builder.toString();
        }
    }

    public static class U2FException extends RuntimeException {
        public U2FException() {
            super();
        }

        public U2FException(String mes) {
            super(mes);
        }
    }

    public static class U2FNoKeyException extends U2FException {
        public U2FNoKeyException() {
            super();
        }
    }

    public static class U2FUserPresenceException extends U2FException {
        public U2FUserPresenceException() {
            super();
        }
    }
}
