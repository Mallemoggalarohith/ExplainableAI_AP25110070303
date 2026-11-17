package com.threatprio.exception;

/** Checked application exception used for data, database and model failures. */
public class ThreatPrioException extends Exception {
    public ThreatPrioException(String message) { super(message); }
    public ThreatPrioException(String message, Throwable cause) { super(message, cause); }
}
