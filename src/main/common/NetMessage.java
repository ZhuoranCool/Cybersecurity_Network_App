package main.common;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class NetMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    public String type;
    public String requestId;
    public String status; // "OK" or "ERROR" for responses
    public String errorCode;
    public String errorMessage;
    public Map<String, Object> payload;

    public NetMessage() {
        this.payload = new HashMap<>();
    }

    public static NetMessage request(String type) {
        NetMessage m = new NetMessage();
        m.type = type;
        m.requestId = UUID.randomUUID().toString();
        return m;
    }

    public static NetMessage ok(String requestId) {
        NetMessage m = new NetMessage();
        m.status = "OK";
        m.requestId = requestId;
        return m;
    }

    public static NetMessage err(String requestId, String code, String msg) {
        NetMessage m = new NetMessage();
        m.status = "ERROR";
        m.requestId = requestId;
        m.errorCode = code;
        m.errorMessage = msg;
        return m;
    }

    @Override
    public String toString() {
        return "NetMessage{type=" + type + ", requestId=" + requestId +
                ", status=" + status + ", errorCode=" + errorCode +
                ", payload=" + payload + "}";
    }
}