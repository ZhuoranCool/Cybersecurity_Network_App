package main.rs;

import main.common.NetMessage;
import main.common.MessageTypes;

import java.io.ObjectOutputStream;
import java.net.Socket;

public class ResourceServerSignalSender implements Runnable {

    private final String host;
    private final int port;
    private final int rsListenPort;

    public ResourceServerSignalSender(String host, int port, int rsListenPort) {
        this.host = host;
        this.port = port;
        this.rsListenPort = rsListenPort;
    }

    @Override
    public void run() {

        System.out.println("[RS] Heartbeat sender -> " + host + ":" + port);

        // loop forever because this is just a periodic signal
        while (true) {

            try (
                // open connection to whoever is listening (AS or client)
                Socket sock = new Socket(host, port);

                // create ObjectOutputStream first
                ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
            ) {

                // build heartbeat message using shared NetMessage format
                NetMessage hb = NetMessage.request(MessageTypes.RS_HEARTBEAT);

                // include useful info in payload
                hb.payload.put("rsPort", rsListenPort);
                hb.payload.put("ts", System.currentTimeMillis());

                out.writeObject(hb);
                out.flush();

                System.out.println("[RS] Sent heartbeat: " + hb);

            } catch (Exception e) {
                // if receiver isn't up yet this will fail -- just try again next second
                System.out.println("[RS] Heartbeat failed: " + e.getMessage());
            }

            try {
                Thread.sleep(1000); // 1 second interval
            } catch (InterruptedException ignored) {}
        }
    }
}