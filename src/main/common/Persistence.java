package main.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class Persistence {

    public static synchronized <T extends Serializable> void saveAtomic(T obj, String path) throws IOException {
        File target = new File(path);
        File parent = target.getParentFile();
        if (parent != null) parent.mkdirs();

        File tmp = new File(path + ".tmp");
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(tmp))) {
            out.writeObject(obj);
            out.flush();
        }
        Files.move(tmp.toPath(), Path.of(path), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    @SuppressWarnings("unchecked")
    public static synchronized <T> T loadOrDefault(String path, T defaultValue) {
        File f = new File(path);
        if (!f.exists()) return defaultValue;
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(f))) {
            return (T) in.readObject();
        } catch (Exception e) {
            return defaultValue;
        }
    }
}