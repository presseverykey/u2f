package com.presseverykey.u2f;

/**
 * see:
 * https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html
 * https://fidoalliance.org/specs/u2f-specs-master/inc/u2f.h
 * Created by a2800276 on 2015-10-29.
 */
public class Constants {

    public static final byte U2F_CLASS = 0x00;
    // CMDs
    public static final byte U2F_REGISTER = 0x01;    // Registration command
    public static final byte U2F_AUTHENTICATE = 0x02;    // Authenticate/sign command
    public static final byte U2F_VERSION = 0x03;    // Read version string command
    public static final byte U2F_CHECK_REGISTER = 0x04;    // Registration command that incorporates checking key handles
    public static final byte U2F_AUTHENTICATE_BATCH = 0x05;    // Authenticate/sign command for a batch of key handles
    public static final byte U2F_VENDOR_FIRST = (byte) 0xc0;    // First vendor defined command
    public static final byte U2F_VENDOR_LAST = (byte) 0xff;    // Last vendor defined command


    // U2F_CMD_REGISTER command defines

    public static final byte U2F_REGISTER_ID = 0x05;    // Version 2 registration identifier
    public static final byte U2F_REGISTER_HASH_ID = 0x00;    // Version 2 hash identintifier

    // Authentication control byte

    public static final byte U2F_AUTH_ENFORCE = 0x03;    // Enforce user presence and sign
    public static final byte U2F_AUTH_CHECK_ONLY = 0x07;    // Check only
    public static final byte U2F_AUTH_FLAG_TUP = 0x01;    // Test of user presence set

    public static final byte[] U2F_SW_NO_ERROR = {(byte) 0x90, (byte) 0x00}; // SW_NO_ERROR
    public static final byte[] U2F_SW_WRONG_DATA = {(byte) 0x6A, (byte) 0x80}; // SW_WRONG_DATA
    public static final byte[] U2F_SW_CONDITIONS_NOT_SATISFIED = {(byte) 0x69, (byte) 0x85}; // SW_CONDITIONS_NOT_SATISFIED
    public static final byte[] U2F_SW_COMMAND_NOT_ALLOWED = {(byte) 0x69, (byte) 0x86}; // SW_COMMAND_NOT_ALLOWED
    public static final byte[] U2F_SW_INS_NOT_SUPPORTED = {(byte) 0x6D, (byte) 0x00}; // SW_INS_NOT_SUPPORTED

    public static final byte[] U2F_VERSION_BYTES = "U2F_V2".getBytes();
    public static final byte[] U2F_EMPTY = new byte[0];

    public static void main(String[] args) {

    }

    public static void p(Object o) {
        System.out.println(o);
    }
}
