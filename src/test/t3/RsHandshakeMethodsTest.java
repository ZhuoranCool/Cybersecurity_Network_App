package test.t3;

import main.client.ClientCLI;
import main.rs.ResourceServer;
import main.common.SecurityUtil;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

public class RsHandshakeMethodsTest {

    private ClientCLI client;
    private ResourceServer rs;

    @Before
    public void setUp() throws Exception {
        client = new ClientCLI("127.0.0.1", 9000, "127.0.0.1", 9001);

        Path tempDir = Files.createTempDirectory("rs-pure-test-");
        Path tempState = tempDir.resolve("state.db");
        rs = new ResourceServer(9001, tempState.toString(), null, -1);
    }

    // server signature verification

    @Test
    public void acceptValidServerSignature() throws Exception {
        String rsId = "rs-1";
        String clientVersion = "1.0";
        List<String> supportedAlgorithms = List.of("RSA", "SHA256");
        String nc = "Nc12345678901234";
        String clientEphemeral = "clientEphemeralKeyB64";
        String serverVersion = "1.0";
        List<String> selectedAlgorithms = List.of("RSA", "SHA256");
        String ns = "Ns12345678901234";
        String serverEphemeral = "serverEphemeralKeyB64";

        String payload = client.buildServerHelloSigningPayload(
                rsId,
                clientVersion,
                supportedAlgorithms,
                nc,
                clientEphemeral,
                serverVersion,
                selectedAlgorithms,
                ns,
                serverEphemeral
        );

        String payloadHashHex = SecurityUtil.sha256(payload);
        byte[] signingPayload = payloadHashHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        KeyPair rsKeyPair = SecurityUtil.generateRSAKeyPair();
        byte[] sig = SecurityUtil.rsaSignPSS(signingPayload, rsKeyPair.getPrivate());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        client.verifyServerHelloSignature(
                rsKeyPair.getPublic(),
                rsId,
                clientVersion,
                supportedAlgorithms,
                nc,
                clientEphemeral,
                serverVersion,
                selectedAlgorithms,
                ns,
                serverEphemeral,
                sigB64
        );
    }

    @Test
    public void rejectWrongTrustedPublicKey() throws Exception {
        String rsId = "rs-1";
        String clientVersion = "1.0";
        List<String> supportedAlgorithms = List.of("RSA", "SHA256");
        String nc = "Nc12345678901234";
        String clientEphemeral = "clientEphemeralKeyB64";
        String serverVersion = "1.0";
        List<String> selectedAlgorithms = List.of("RSA", "SHA256");
        String ns = "Ns12345678901234";
        String serverEphemeral = "serverEphemeralKeyB64";

        String payload = client.buildServerHelloSigningPayload(
                rsId,
                clientVersion,
                supportedAlgorithms,
                nc,
                clientEphemeral,
                serverVersion,
                selectedAlgorithms,
                ns,
                serverEphemeral
        );

        String payloadHashHex = SecurityUtil.sha256(payload);
        byte[] signingPayload = payloadHashHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        KeyPair realRsKeyPair = SecurityUtil.generateRSAKeyPair();
        byte[] sig = SecurityUtil.rsaSignPSS(signingPayload, realRsKeyPair.getPrivate());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        KeyPair wrongTrustedKeyPair = SecurityUtil.generateRSAKeyPair();
        PublicKey wrongTrustedPk = wrongTrustedKeyPair.getPublic();

        try {
            client.verifyServerHelloSignature(
                    wrongTrustedPk,
                    rsId,
                    clientVersion,
                    supportedAlgorithms,
                    nc,
                    clientEphemeral,
                    serverVersion,
                    selectedAlgorithms,
                    ns,
                    serverEphemeral,
                    sigB64
            );
            Assert.fail("Expected signature verification to fail with wrong trusted public key");
        } catch (Exception e) {
            Assert.assertTrue(
                    "Expected signature-related failure, but got: " + e.getMessage(),
                    e.getMessage() != null &&
                    (e.getMessage().toLowerCase().contains("signature")
                     || e.getMessage().toLowerCase().contains("verify"))
            );
        }
    }

    @Test
    public void rejectTamperedNonceInSignedPayload() throws Exception {
        String rsId = "rs-1";
        String clientVersion = "1.0";
        List<String> supportedAlgorithms = List.of("RSA", "SHA256");
        String nc = "Nc12345678901234";
        String clientEphemeral = "clientEphemeralKeyB64";
        String serverVersion = "1.0";
        List<String> selectedAlgorithms = List.of("RSA", "SHA256");
        String nsSigned = "Ns12345678901234";
        String nsVerified = "Ns99999999999999";
        String serverEphemeral = "serverEphemeralKeyB64";

        String payload = client.buildServerHelloSigningPayload(
                rsId,
                clientVersion,
                supportedAlgorithms,
                nc,
                clientEphemeral,
                serverVersion,
                selectedAlgorithms,
                nsSigned,
                serverEphemeral
        );

        String payloadHashHex = SecurityUtil.sha256(payload);
        byte[] signingPayload = payloadHashHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        KeyPair rsKeyPair = SecurityUtil.generateRSAKeyPair();
        byte[] sig = SecurityUtil.rsaSignPSS(signingPayload, rsKeyPair.getPrivate());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        try {
            client.verifyServerHelloSignature(
                    rsKeyPair.getPublic(),
                    rsId,
                    clientVersion,
                    supportedAlgorithms,
                    nc,
                    clientEphemeral,
                    serverVersion,
                    selectedAlgorithms,
                    nsVerified, // here modified
                    serverEphemeral,
                    sigB64
            );
            Assert.fail("Expected signature verification to fail after tampering with Ns");
        } catch (Exception e) {
            Assert.assertTrue(
                    "Expected signature-related failure, but got: " + e.getMessage(),
                    e.getMessage() != null &&
                    (e.getMessage().toLowerCase().contains("signature")
                     || e.getMessage().toLowerCase().contains("verify"))
            );
        }
    }

    @Test
    public void rejectUnsupportedSelectedAlgorithm() throws Exception {
        String rsId = "rs-1";
        String clientVersion = "1.0";
        List<String> supportedAlgorithms = List.of("RSA", "SHA256");
        String nc = "Nc12345678901234";
        String clientEphemeral = "clientEphemeralKeyB64";
        String serverVersion = "1.0";
        List<String> selectedAlgorithms = List.of("RSA", "FAKE_ALG");
        String ns = "Ns12345678901234";
        String serverEphemeral = "serverEphemeralKeyB64";

        String payload = client.buildServerHelloSigningPayload(
                rsId,
                clientVersion,
                supportedAlgorithms,
                nc,
                clientEphemeral,
                serverVersion,
                selectedAlgorithms,
                ns,
                serverEphemeral
        );

        String payloadHashHex = SecurityUtil.sha256(payload);
        byte[] signingPayload = payloadHashHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        KeyPair rsKeyPair = SecurityUtil.generateRSAKeyPair();
        byte[] sig = SecurityUtil.rsaSignPSS(signingPayload, rsKeyPair.getPrivate());
        String sigB64 = Base64.getEncoder().encodeToString(sig);

        try {
            client.verifyServerHelloSignature(
                    rsKeyPair.getPublic(),
                    rsId,
                    clientVersion,
                    supportedAlgorithms,
                    nc,
                    clientEphemeral,
                    serverVersion,
                    selectedAlgorithms,
                    ns,
                    serverEphemeral,
                    sigB64
            );
            Assert.fail("Expected verification to fail because server selected an unsupported algorithm");
        } catch (Exception e) {
            Assert.assertTrue(
                    "Expected unsupported algorithm failure, but got: " + e.getMessage(),
                    e.getMessage() != null &&
                    e.getMessage().toLowerCase().contains("unsupported")
            );
        }
    }

    // session key establishment

    @Test
    public void deriveSameSessionKeyOnClientAndServer() throws Exception {
        SecretKey preMaster = SecurityUtil.generateAESKey();

        SecretKey k1 = client.deriveSessionKey(preMaster, "Nc12345678901234", "Ns12345678901234");
        SecretKey k2 = rs.deriveSessionKey(preMaster, "Nc12345678901234", "Ns12345678901234");

        Assert.assertArrayEquals(k1.getEncoded(), k2.getEncoded());
    }

    @Test
    public void deriveDifferentSessionKeyWhenServerNonceChanges() throws Exception {
        SecretKey preMaster = SecurityUtil.generateAESKey();

        SecretKey k1 = client.deriveSessionKey(preMaster, "Nc12345678901234", "Ns12345678901234");
        SecretKey k2 = rs.deriveSessionKey(preMaster, "Nc12345678901234", "Ns99999999999999");

        Assert.assertFalse(java.util.Arrays.equals(k1.getEncoded(), k2.getEncoded()));
    }
}