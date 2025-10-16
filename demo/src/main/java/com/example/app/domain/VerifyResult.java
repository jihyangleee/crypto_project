package com.example.app.domain;

public class VerifyResult {
    private final String signerDigestHex;
    private final String localDigestHex;
    private final boolean matches;

    public VerifyResult(String signerDigestHex, String localDigestHex, boolean matches) {
        this.signerDigestHex = signerDigestHex;
        this.localDigestHex = localDigestHex;
        this.matches = matches;
    }

    public String getSignerDigestHex() { return signerDigestHex; }
    public String getLocalDigestHex() { return localDigestHex; }
    public boolean isMatches() { return matches; }
}
