package test.t3;

import main.client.ClientCLI;
import main.rs.ResourceServer;
import main.common.SecurityUtil;

import org.junit.Test;
import org.junit.Assert;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;

public class RsHandshakeTest {

    private static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private static void startRsInBackground(int port, String statePath) throws Exception {
        final java.util.concurrent.atomic.AtomicReference<Throwable> startupError = new java.util.concurrent.atomic.AtomicReference<>();

        Thread t = new Thread(() -> {
            try {
                ResourceServer rs = new ResourceServer(port, statePath, null, -1);
                rs.start();
            } catch (Throwable e) {
                startupError.set(e);
                e.printStackTrace();
            }
        });

        t.setDaemon(true);
        t.start();

        Thread.sleep(1000);

        if (startupError.get() != null) {
            throw new RuntimeException("RS failed to start", startupError.get());
        }
    }

    @Test
    public void acceptRealResourceServer() throws Exception {
        int rsPort = freePort();
        Path tempState = Files.createTempFile("rs-state-", ".db");

        startRsInBackground(rsPort, tempState.toString());

        ClientCLI client = new ClientCLI("127.0.0.1", 9000, "127.0.0.1", rsPort);

        PublicKey trustedPk = ClientCLI.loadRSPublicKey("data/keys/rs_public.key");

        client.verifyRSPossessionHandshake(trustedPk);

        Assert.assertTrue(true);
    }

    @Test
    public void rejectWrongTrustedKey() throws Exception {
        int rsPort = freePort();
        Path tempState = Files.createTempFile("rs-state-", ".db");

        startRsInBackground(rsPort, tempState.toString());

        ClientCLI client = new ClientCLI("127.0.0.1", 9000, "127.0.0.1", rsPort);

        KeyPair fake = SecurityUtil.generateRSAKeyPair();
        PublicKey wrongPk = fake.getPublic();

        boolean failed = false;
        try {
            client.verifyRSPossessionHandshake(wrongPk);
        } catch (Exception e) {
            failed = true;
        }

        Assert.assertTrue("Expected handshake to fail with wrong trusted RS public key", failed);
    }
}