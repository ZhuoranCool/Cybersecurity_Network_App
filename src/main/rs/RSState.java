package main.rs;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class RSState implements Serializable {
    private static final long serialVersionUID = 1L;

    // key = course + "::" + title
    public Map<String, StoredPost> posts = new HashMap<>();
}