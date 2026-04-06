package main.common;

import java.io.Serializable;

public class SecureEnvelope implements Serializable {
    private static final long serialVersionUID = 1L;

    public byte[] iv;
    public byte[] ciphertext;

    public SecureEnvelope() {}

    public SecureEnvelope(byte[] iv, byte[] ciphertext) {
        this.iv = iv;
        this.ciphertext = ciphertext;
    }
}