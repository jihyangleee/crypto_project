# Secure Chat Demo (JavaFX)

This is a minimal demo scaffold generated from `system.yaml`.

How to run (development):

1. Build with Gradle (in `demo`):

```powershell
./gradlew.bat clean build
```

2. Run the JavaFX application (Gradle application plugin should be configured in the project):

```powershell
./gradlew.bat run
```

Notes:
- This scaffold contains UI, controller, simple RSA/AES model stubs and network stubs (no real socket implementation yet).
- Use the "Key generation" button to generate a keypair (demo uses Java KeyPairGenerator and returns a PEM-like public key string).
- Chat and File send are stubs that echo local actions; network and persistent storage need to be implemented as next steps.
