package main.common;

public class MessageTypes {
    
    public static final String REGISTER_REQ = "REGISTER_REQ";
    public static final String LOGIN_REQ = "LOGIN_REQ";
    public static final String TOKEN_ISSUE_REQ = "TOKEN_ISSUE_REQ";
    public static final String TOKEN_VALIDATE_REQ = "TOKEN_VALIDATE_REQ";
    public static final String KEY_EXCHANGE_REQ = "KEY_EXCHANGE_REQ";
    public static final String KEY_EXCHANGE_RESP = "KEY_EXCHANGE_RESP";

    public static final String COURSE_LIST_REQ = "COURSE_LIST_REQ";
    public static final String COURSE_JOIN_REQ = "COURSE_JOIN_REQ";
    public static final String COURSE_DROP_REQ = "COURSE_DROP_REQ";
    public static final String COURSE_ROSTER_REQ = "COURSE_ROSTER_REQ";
    public static final String COURSE_UNENROLL_REQ = "COURSE_UNENROLL_REQ";
    public static final String COURSE_ENROLL_REQ = "COURSE_ENROLL_REQ";

    public static final String COURSE_ADD_REQ = "COURSE_ADD_REQ";
    public static final String COURSE_DEL_REQ = "COURSE_DEL_REQ";

    public static final String ADMIN_CREATE_USER_REQ = "ADMIN_CREATE_USER_REQ";
    public static final String ADMIN_DELETE_USER_REQ = "ADMIN_DELETE_USER_REQ";
    public static final String ADMIN_MOVE_USER_REQ = "ADMIN_MOVE_USER_REQ";
    public static final String ADMIN_LIST_USERS_REQ = "ADMIN_LIST_USERS_REQ";

    public static final String RESOURCE_CREATE_REQ = "RESOURCE_CREATE_REQ";
    public static final String RESOURCE_READ_REQ = "RESOURCE_READ_REQ";
    public static final String RESOURCE_UPDATE_REQ = "RESOURCE_UPDATE_REQ";
    public static final String RESOURCE_DELETE_REQ = "RESOURCE_DELETE_REQ";
    public static final String RS_HEARTBEAT = "RS_HEARTBEAT";

    public static final String VERIFY_RS_REQ = "VERIFY_RS_REQ";

    public static final String SUCCESS = "SUCCESS";
    public static final String ERROR_DB_UNKNOWN = "ERROR_DB_UNKNOWN";
    public static final String ERROR_DB_CONNECT = "ERROR_DB_CONNECT";
    public static final String ERROR_DB_STATEMENT = "ERROR_DB_STATEMENT";
    public static final String ERROR_DB_USER_NOT_FOUND = "ERROR_DB_USER_NOT_FOUND";
    public static final String ERROR_DB_FILE_DUPLICATE = "ERROR_DB_FILE_DUPLICATE";
    public static final String ERROR_DB_FILE_NOT_EXIST = "ERROR_DB_FILE_NOT_EXIST";
    public static final String ERROR_DB_FILE_NO_READ_PERMISSION = "ERROR_DB_FILE_NO_READ_PERMISSION";
    public static final String ERROR_DB_FILE_NO_WRITE_PERMISSION = "ERROR_DB_FILE_NO_WRITE_PERMISSION";
    public static final String ERROR_DB_FILE_NO_DELETE_PERMISSION = "ERROR_DB_FILE_NO_DELETE_PERMISSION";

    public static final String ERROR_BAD_COURSE_CODE = "ERROR_BAD_COURSE_CODE";
    public static final String ERROR_NOT_ENROLLED = "ERROR_NOT_ENROLLED";
    public static final String ERROR_NOT_TEACHER = "ERROR_NOT_TEACHER";
    public static final String ERROR_BAD_TAG = "ERROR_BAD_TAG";
    public static final String ERROR_NOT_TEACHER_OR_ADMIN = "ERROR_NOT_TEACHER_OR_ADMIN";
    public static final String ERROR_NOT_ADMIN = "ERROR_NOT_ADMIN";

    // auth
    public static final String RS_CERT_REQUEST = "RS_CERT_REQUEST";
    public static final String RS_CERT_RESPONSE = "RS_CERT_RESPONSE";
    public static final String RS_CLIENT_HELLO_REQ = "RS_CLIENT_HELLO_REQ";
    public static final String RS_SERVER_HELLO_RESP = "RS_SERVER_HELLO_RESP";
    public static final String RS_CLIENT_KEY_REQ = "RS_CLIENT_KEY_REQ";
    public static final String RS_FINISHED_RESP = "RS_FINISHED_RESP";
}