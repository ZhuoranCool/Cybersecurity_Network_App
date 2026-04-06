package main.common.auth;

import java.io.Serializable;

public class RsCertificate implements Serializable {
    private static final long serialVersionUID = 1L;

    public String subject;
    public String issuer;
    public String hostname;
    public int port;
    public String publicKeyB64;
    public long validFrom;
    public long validTo;
    public String serialNumber;
    public String signatureB64;

    public RsCertificate() {}

    public RsCertificate(
        String subject,
        String issuer,
        String hostname,
        int port,
        String publicKeyB64,
        long validFrom,
        long validTo,
        String serialNumber,
        String signatureB64
    ) {
        this.subject = subject;
        this.issuer = issuer;
        this.hostname = hostname;
        this.port = port;
        this.publicKeyB64 = publicKeyB64;
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.serialNumber = serialNumber;
        this.signatureB64 = signatureB64;
    }

    public String signingPayload() {
        return subject + "|" +
               issuer + "|" +
               hostname + "|" +
               port + "|" +
               publicKeyB64 + "|" +
               validFrom + "|" +
               validTo + "|" +
               serialNumber;
    }
}
