package main.rs;

import java.io.Serializable;

public class StoredPost implements Serializable {
    private static final long serialVersionUID = 1L;

    public String course;
    public String title;
    public String content;

    public String tag;          // assignment/test/project
    public String author;
    public String authorRole;   // STUDENT/TA/TEACHER

    public long createdAt;
    public long updatedAt;

    public StoredPost(String course, String title, String content, String tag,
                      String author, String authorRole) {
        this.course = course;
        this.title = title;
        this.content = content;
        this.tag = tag;
        this.author = author;
        this.authorRole = authorRole;
        this.createdAt = System.currentTimeMillis();
        this.updatedAt = this.createdAt;
    }
}