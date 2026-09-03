package android.os;

/**
 * Compile-time stub for Android's hidden binder exception used by keystore2 to return
 * service-specific (including KeyMint) error codes.
 */
public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;

    public ServiceSpecificException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
