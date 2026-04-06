package main.common.auth;

import java.io.Serializable;

public class CertificateRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    public String rsId;
    public String publicKeyB64;
    public String hostname;
    public int port;
    public long requestValidFrom;
    public long requestValidTo;

    public CertificateRequest() {}

    public CertificateRequest(
        String rsId,
        String publicKeyB64,
        String hostname,
        int port,
        long requestValidFrom,
        long requestValidTo
    ) {
        this.rsId = rsId;
        this.publicKeyB64 = publicKeyB64;
        this.hostname = hostname;
        this.port = port;
        this.requestValidFrom = requestValidFrom;
        this.requestValidTo = requestValidTo;
    }
}
