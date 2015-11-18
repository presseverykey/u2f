package com.presseverykey.u2f;

import static de.kuriositaet.util.crypto.Util.b2h;

/**
 * Created by a2800276 on 2015-10-29.
 */
public class U2F {
    public static class RegistrationRequestMessage {
        public RegistrationRequestMessage(byte[] bytes) {
            if (bytes == null || bytes.length != 64) {
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

        public byte[] toBytes() {
            int len = 64 + 1 + this.keyHandle.length;
            byte[] bs = new byte[len];
            System.arraycopy(this.getChallengeParameter(), 0, bs, 0, 32);
            System.arraycopy(this.getApplicationParameter(), 0, bs, 32, 32);
            bs[64] = (byte) this.getKeyHandle().length;
            System.arraycopy(this.getKeyHandle(), 0, bs, 65, this.getKeyHandle().length);
            return bs;
        }
    }

    public static class RegistrationResponseMessage {
        private static final int PK_LEN = 65;
        private byte[] userPK;
        private byte[] keyHandle;
        private byte[] attestationCert;
        private byte[] signature;

        public byte[] toBytes() {
            int len = 1 + PK_LEN + 1 + getKeyHandle().length + getAttestationCert().length + getSignature().length;
            int pos = 0;
            byte[] bytes = new byte[len];
            bytes[pos] = 0x05;
            pos += 1;
            System.arraycopy(getUserPK(), 0, bytes, pos, PK_LEN);
            pos += PK_LEN;
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
            builder.append(b2h(getUserPK()));
            builder.append("\n");
            builder.append("keyHandle:");
            builder.append(b2h(getKeyHandle()));
            builder.append("\n");
            builder.append("attestationCert:");
            builder.append(b2h(getAttestationCert()));
            builder.append("\n");
            builder.append("signature:");
            builder.append(b2h(getSignature()));
            builder.append("\n");
            return builder.toString();
        }

        public byte[] getUserPK() {
            return userPK;
        }

        public void setUserPK(byte[] userPK) {
            if (userPK == null || userPK.length != PK_LEN) {
                throw new U2FException("invalid pk");
            }
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
            int len = 1 + 4 + signature.length;
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
            builder.append("counter: " + b2h(counter) + "\n");
            builder.append("signature: " + b2h(signature) + "\n");
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
