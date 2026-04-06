package test.t3;

import main.client.ClientCLI;
import main.rs.ResourceServer;
import main.common.SecurityUtil;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class RsFinishedTest {

    private ClientCLI client;
    private ResourceServer rs;

    @Before
    public void setUp() throws Exception {
        client = new ClientCLI("127.0.0.1", 9000, "127.0.0.1", 9001);

        Path tempDir = Files.createTempDirectory("rs-finished-test-");
        Path tempState = tempDir.resolve("state.db");
        rs = new ResourceServer(9001, tempState.toString(), null, -1);
    }

    @Test
    public void clientAndServerShouldComputeSameClientFinished() throws Exception {
        SecretKey sessionKey = SecurityUtil.generateAESKey();
        byte[] transcript = "handshake-transcript-1".getBytes(StandardCharsets.UTF_8);

        String c = client.computeFinished("client finished", sessionKey, transcript);
        String s = rs.computeFinished("client finished", sessionKey, transcript);

        Assert.assertEquals(c, s);
    }

    @Test
    public void clientAndServerShouldComputeSameServerFinished() throws Exception {
        SecretKey sessionKey = SecurityUtil.generateAESKey();
        byte[] transcript = "handshake-transcript-2".getBytes(StandardCharsets.UTF_8);

        String c = client.computeFinished("server finished", sessionKey, transcript);
        String s = rs.computeFinished("server finished", sessionKey, transcript);

        Assert.assertEquals(c, s);
    }

    @Test
    public void finishedShouldDifferWhenTranscriptChanges() throws Exception {
        SecretKey sessionKey = SecurityUtil.generateAESKey();

        byte[] transcript1 = "handshake-transcript-A".getBytes(StandardCharsets.UTF_8);
        byte[] transcript2 = "handshake-transcript-B".getBytes(StandardCharsets.UTF_8);

        String f1 = client.computeFinished("client finished", sessionKey, transcript1);
        String f2 = rs.computeFinished("client finished", sessionKey, transcript2);

        Assert.assertNotEquals(f1, f2);
    }

    @Test
    public void finishedShouldDifferWhenLabelChanges() throws Exception {
        SecretKey sessionKey = SecurityUtil.generateAESKey();
        byte[] transcript = "same-transcript".getBytes(StandardCharsets.UTF_8);

        String clientFinished = client.computeFinished("client finished", sessionKey, transcript);
        String serverFinished = rs.computeFinished("server finished", sessionKey, transcript);

        Assert.assertNotEquals(clientFinished, serverFinished);
    }

    @Test
    public void finishedShouldDifferWhenSessionKeyChanges() throws Exception {
        SecretKey sessionKey1 = SecurityUtil.generateAESKey();
        SecretKey sessionKey2 = SecurityUtil.generateAESKey();
        byte[] transcript = "same-transcript".getBytes(StandardCharsets.UTF_8);

        String f1 = client.computeFinished("client finished", sessionKey1, transcript);
        String f2 = rs.computeFinished("client finished", sessionKey2, transcript);

        Assert.assertNotEquals(f1, f2);
    }

    @Test
    public void finishedShouldMatchForDerivedSessionKeyOnBothSides() throws Exception {
        SecretKey preMaster = SecurityUtil.generateAESKey();
        String nc = "Nc12345678901234";
        String ns = "Ns12345678901234";
        byte[] transcript = "full-handshake-transcript".getBytes(StandardCharsets.UTF_8);

        SecretKey clientSessionKey = client.deriveSessionKey(preMaster, nc, ns);
        SecretKey serverSessionKey = rs.deriveSessionKey(preMaster, nc, ns);

        String clientFinished = client.computeFinished("client finished", clientSessionKey, transcript);
        String serverFinished = rs.computeFinished("client finished", serverSessionKey, transcript);

        Assert.assertEquals(clientFinished, serverFinished);
    }
}