package com.example.app.domain;

import javafx.beans.property.*;

public class KeyInfo {
    private final StringProperty algorithm = new SimpleStringProperty("");
    private final IntegerProperty keyLength = new SimpleIntegerProperty(0);
    private final StringProperty fingerprintHex = new SimpleStringProperty("");
    private final StringProperty publicKeyPem = new SimpleStringProperty("");
    private final BooleanProperty hasPrivateKey = new SimpleBooleanProperty(false);

    public KeyInfo() {}

    public KeyInfo(String algorithm, int keyLength, String fingerprintHex, String publicKeyPem, boolean hasPrivateKey) {
        setAlgorithm(algorithm);
        setKeyLength(keyLength);
        setFingerprintHex(fingerprintHex);
        setPublicKeyPem(publicKeyPem);
        setHasPrivateKey(hasPrivateKey);
    }

    // Algorithm
    public String getAlgorithm() { return algorithm.get(); }
    public void setAlgorithm(String value) { algorithm.set(value); }
    public StringProperty algorithmProperty() { return algorithm; }

    // Key Length
    public int getKeyLength() { return keyLength.get(); }
    public void setKeyLength(int value) { keyLength.set(value); }
    public IntegerProperty keyLengthProperty() { return keyLength; }

    // Fingerprint
    public String getFingerprintHex() { return fingerprintHex.get(); }
    public void setFingerprintHex(String value) { fingerprintHex.set(value); }
    public StringProperty fingerprintHexProperty() { return fingerprintHex; }

    // Public Key PEM
    public String getPublicKeyPem() { return publicKeyPem.get(); }
    public void setPublicKeyPem(String value) { publicKeyPem.set(value); }
    public StringProperty publicKeyPemProperty() { return publicKeyPem; }

    // Has Private Key
    public boolean isHasPrivateKey() { return hasPrivateKey.get(); }
    public void setHasPrivateKey(boolean value) { hasPrivateKey.set(value); }
    public BooleanProperty hasPrivateKeyProperty() { return hasPrivateKey; }
}
