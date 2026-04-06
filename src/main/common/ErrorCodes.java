package main.common;

public class ErrorCodes {
    public static final String BAD_REQUEST = "BAD_REQUEST";
    public static final String UNAUTHORIZED = "UNAUTHORIZED";
    public static final String FORBIDDEN = "FORBIDDEN";
    public static final String NOT_FOUND = "NOT_FOUND";
    public static final String ALREADY_EXISTS = "ALREADY_EXISTS";
    public static final String INTERNAL = "INTERNAL";
    public static final String UNKNOWN_TYPE = "UNKNOWN_TYPE";

    public static final String NOT_ADMIN = "NOT_ADMIN";
    public static final String NOT_ENROLLED = "NOT_ENROLLED";
    public static final String BAD_COURSE_CODE = "BAD_COURSE_CODE";
    public static final String BAD_ROLE = "BAD_ROLE";
    public static final String INVALID_STATE = "INVALID_STATE";

    // DB ERROR
    public static final String ERROR_DB_CONNECT = "ERROR_DB_CONNECT";
    public static final String ERROR_DB_STATEMENT = "ERROR_DB_STATEMENT";
    public static final String ERROR_DB_USER_NOT_FOUND = "ERROR_DB_USER_NOT_FOUND";
    public static final String ERROR_DB_FILE_DUPLICATE = "ERROR_DB_FILE_DUPLICATE";
}