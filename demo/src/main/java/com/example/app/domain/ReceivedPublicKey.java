package com.example.app.domain;

import java.time.Instant;

public class ReceivedPublicKey {
    private final String alias;
    private final String fingerprint;
    private final Instant receivedDate;
    private final String publicKeyPem;
    private boolean trusted;

    public ReceivedPublicKey(String alias, String fingerprint, Instant receivedDate, String publicKeyPem) {
        this.alias = alias;
        this.fingerprint = fingerprint;
        this.receivedDate = receivedDate;
        this.publicKeyPem = publicKeyPem;
        this.trusted = false;
    }

    // Getters
    public String getAlias() { return alias; }
    public String getFingerprint() { return fingerprint; }
    public Instant getReceivedDate() { return receivedDate; }
    public String getPublicKeyPem() { return publicKeyPem; }
    public boolean isTrusted() { return trusted; }
    public void setTrusted(boolean trusted) { this.trusted = trusted; }
}
