package com.example.app.domain;

import java.time.Instant;
import java.util.UUID;

public class Packet {
    private final UUID id;
    private final Instant time;
    private final boolean hasSignature;
    private final String algoSummary;
    private final String base64Cipher;
    private final String base64WrappedKey;
    private final String base64Signature;
    private final String ivBase64;
    private final long sizeBytes;
    private final String source; // "TX" or "RX"
    private String plaintext; // For decrypted content
    private String ciphertext; // For encrypted content display

    public Packet(UUID id, Instant time, boolean hasSignature, String algoSummary,
                  String base64Cipher, String base64WrappedKey, String base64Signature,
                  String ivBase64, long sizeBytes, String source) {
        this.id = id;
        this.time = time;
        this.hasSignature = hasSignature;
        this.algoSummary = algoSummary;
        this.base64Cipher = base64Cipher;
        this.base64WrappedKey = base64WrappedKey;
        this.base64Signature = base64Signature;
        this.ivBase64 = ivBase64;
        this.sizeBytes = sizeBytes;
        this.source = source;
    }

    // Getters
    public UUID getId() { return id; }
    public Instant getTime() { return time; }
    public boolean isHasSignature() { return hasSignature; }
    public String getAlgoSummary() { return algoSummary; }
    public String getBase64Cipher() { return base64Cipher; }
    public String getBase64WrappedKey() { return base64WrappedKey; }
    public String getBase64Signature() { return base64Signature; }
    public String getIvBase64() { return ivBase64; }
    public long getSizeBytes() { return sizeBytes; }
    public String getSource() { return source; }
    public String getPlaintext() { return plaintext; }
    public void setPlaintext(String plaintext) { this.plaintext = plaintext; }
    public String getCiphertext() { return ciphertext; }
    public void setCiphertext(String ciphertext) { this.ciphertext = ciphertext; }
}
