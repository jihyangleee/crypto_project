# JavaFX RSA/AES Secure Chat & File Transfer — Copilot Request

> 목적: 과제 요구사항(기본 + 확장)을 **JavaFX GUI 데스크톱 앱**으로 완성하기 위한 개발 요청서. VSCode + Copilot 환경에서 이 파일을 참고해 일관된 코드 생성을 유도합니다.  fileciteturn2file0

---

## 0) 과제 맥락 요약 (필수/확장)
- **기본**: Client/Server 소켓 통신, 채팅, 파일 전송, RSA 키쌍 생성/저장/불러오기, 공개키 교환, **AES로 채팅 암호화**, 수신측에서 **암호문과 복호문 동시 표시**.
- **확장**: **Directory Server**(사용자명 ↔ 공개키 저장/조회)를 추가하고, Client가 이름으로 공개키를 요청해 획득. 서버는 자체 저장소 유지.

---

## 1) 최종 목표 (Acceptance Criteria)
다음 항목이 GUI에서 동작하고 시연 가능해야 합니다.

### A. 통신 & 상태
- [ ] 서버 모드에서 특정 포트로 대기, 클라이언트 모드에서 서버 IP/포트로 접속
- [ ] 연결/해제 상태를 GUI에 표시 (상태 라벨/아이콘/로그)
- [ ] 채팅(문자열) 송수신 + 파일 전송(任意 파일)

### B. 암호 기능
- [ ] **RSA 2048** 키쌍 생성, **PEM**(또는 DER)로 **저장/불러오기**
- [ ] **공개키 교환**(연결 시 혹은 버튼으로 수동 전송)
- [ ] **AES 대칭키 암호화 채널**: 채팅 메시지 암/복호
  - 권장: **AES-GCM(128/256)** (무결성 포함). (과제 예제는 AES/ECB이나, 실제 구현은 GCM 권장)
- [ ] 수신측 GUI에 **수신 암호문(hex/base64)** 과 **복호문(평문)** 을 **동시에** 표시
- [ ] 파일 전송 시
  - 옵션1: **RSA로 세션키 교환 후 AES로 파일 암호화**
  - 옵션2: **파일에 전자서명(RSA-SHA256) 부착** (또는 둘 다)

### C. 확장 과제 (Directory Server)
- [ ] 별도 프로세스로 동작하는 **Directory Server** 실행
- [ ] **이름으로 공개키 요청/응답** 가능
- [ ] 서버가 **사용자명↔공개키 저장소**(파일/DB)를 유지
- [ ] 클라이언트에서 **이름 입력 → 공개키 조회 → 캐시 저장/표시**

### D. UI(슬라이드 예시 반영)
- [ ] 모드 전환(클라이언트/서버), 연결 상태/상대 정보 표시
- [ ] 키 생성/로드/세이브, 내 키/상대 키 정보 표시, “공개키 보내기”
- [ ] 채팅 영역(입력창/전송 버튼/로그 뷰어)
- [ ] 파일 선택/전송 버튼, 전송/수신 로그

### E. 제출/재현성
- [ ] **Gradle** 기반 빌드 스크립트 제공, `README`에 실행 방법 기재
- [ ] **Eclipse/VSCode Import 가이드**(프로젝트 구조/의존성) 정리

---

## 2) 아키텍처 (JavaFX 데스크톱, MVC 스타일)

```
app/
 ├─ build.gradle
 ├─ src/main/java/
 │   └─ app/
 │       ├─ Main.java                  // JavaFX 진입점(Stage/Scene)
 │       ├─ controller/
 │       │   ├─ MainController.java    // 연결/키/채팅/파일 전송 UI 이벤트
 │       │   └─ SettingsController.java
 │       ├─ view/                      // FXML & CSS
 │       │   ├─ main.fxml
 │       │   ├─ settings.fxml
 │       │   └─ styles.css
 │       ├─ model/
 │       │   ├─ RSAKeyManager.java     // 키 생성/저장/불러오기(PEM/DER)
 │       │   ├─ AESCipher.java         // AES-GCM (fallback: AES/ECB for demo)
 │       │   ├─ SignatureService.java  // RSA-SHA256 서명/검증
 │       │   └─ MessagePacket.java     // 직렬화용 DTO (JSON)
 │       └─ net/
 │           ├─ ChatServer.java        // ServerSocket accept, 클라 핸들러
 │           ├─ ChatClient.java        // 서버 접속/송수신
 │           ├─ DirectoryClient.java   // Directory Server 쿼리(Client)
 │           └─ Protocol.java          // 프레이밍, JSON, 에러코드 등
 └─ src/main/resources/
     └─ app/view/ (FXML/CSS)
```

- **포트 예시**:  
  - Chat/File Server: `5000`  
  - Directory Server: `6000`
- **데이터 포맷**: JSON Lines(한 메시지 = 한 줄), 바이너리는 base64 또는 첨부 프레임으로 전송.
- **스레딩**: `ChatServer`는 클라이언트별 스레드/Executor, UI 업데이트는 `Platform.runLater`.

---

## 3) 네트워크 프로토콜 (간단 초안)

### 3.1 프레이밍
- 텍스트 라인 기반(JSON) + `\n` 종결
- 필드: `type`, `payload`, `meta`

### 3.2 메시지 타입
```json
// 공개키 교환
{ "type": "PUBKEY", "payload": { "alg": "RSA", "format": "PEM", "key": "<base64-PEM>" } }

// 세션키 교환(RSA로 AES 키 암호화)
{ "type": "SESSKEY", "payload": { "enc": "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "key": "<base64>" } }

// 채팅(암호문 전송)
{ "type": "CHAT", "payload": { "mode": "AES-GCM", "iv": "<b64>", "ct": "<b64>", "aad": "<b64-optional>" } }

// 파일 전송(헤더 + 청크)
{ "type": "FILE_META", "payload": { "name": "report.pdf", "bytes": 123456, "mode": "AES-GCM" } }
{ "type": "FILE_CHUNK", "payload": { "seq": 1, "ct": "<b64>" } }
{ "type": "FILE_END" }
```

### 3.3 무결성/인증
- 권장: **AES-GCM**(내장 태그) 또는 **RSA-SHA256 전자서명** 동봉(`SIGN` 타입).

---

## 4) Directory Server (확장)
- **프로세스**: `directory-server/` (간단한 TCP 또는 HTTP)
- **저장소**: `keys.json` (예: `{ "alice": "-----BEGIN PUBLIC KEY-----..." }`)
- **API (TCP-JSON 예시)**  
  - 요청: `{ "op": "GET", "name": "alice" }`  
  - 응답: `{ "ok": true, "name": "alice", "pubkey": "<PEM>" }` / `{ "ok": false, "error": "NOT_FOUND" }`
- **클라 연동**: JavaFX 앱의 “공개키 조회” 버튼 → DirectoryClient 사용 → 결과 캐시 & 표시.

---

## 5) 보안 스펙
- **RSA**: 2048-bit, OAEP(SHA-256) 권장. (예제는 단순 RSA/ECB, 과제 적합성을 위해 주석으로 안내)
- **AES**: GCM(12-byte IV, 128-bit 태그) 권장. (예제 대비 안전)
- **키 저장**: PEM(SubjectPublicKeyInfo, PKCS#8). 비밀키는 암호로 보호(optional).
- **랜덤**: `SecureRandom`
- **인증서/CA**: 범위 밖(필요 시 자기서명 X.509 확장 가능).

---

## 6) Copilot 지시(주석/프롬프트 예시)

> 아래 코멘트를 파일 상단/클래스 상단에 넣어 Copilot이 맥락을 이해하고 일관되게 생성하도록 합니다.

```java
// GOAL: JavaFX GUI secure chat & file transfer app using RSA key exchange and AES-GCM for encryption.
// REQUIREMENTS:
// - Client/Server socket communication with connect/disconnect UI.
// - RSA 2048 keypair generation, save/load PEM, public key exchange.
// - Encrypted chat (show ciphertext and decrypted text on receiver).
// - Encrypted file transfer using session key (RSA → AES-GCM).
// - Optional: digital signature for integrity; Extended: Directory Server(name→pubkey).
// ARCH: MVC with JavaFX (FXML Views, Controllers, Services). Use separate threads for network I/O.
// Provide Gradle build and README with Eclipse/VSCode import instructions.
```

각 클래스에 구체적으로:
```java
// Copilot: Implement RSAKeyManager with methods:
// - generateKeyPair(int bits)
// - savePublicKeyPEM(PublicKey key, Path out)
// - savePrivateKeyPEM(PrivateKey key, Path out, Optional<char[]> password)
// - loadPublicKeyPEM(Path in)
// - loadPrivateKeyPEM(Path in, Optional<char[]> password)
// - toHex(byte[] b)

// Copilot: Implement AESCipher (GCM) with methods:
// - SecretKey newKey(int bits)
// - byte[] encrypt(SecretKey key, byte[] iv12, byte[] plaintext, byte[] aad)
// - byte[] decrypt(SecretKey key, byte[] iv12, byte[] ciphertext, byte[] aad)
// - byte[] randomIV12()
```

```java
// Copilot: Implement ChatServer with features:
// - start(int port): accept loop with client handler threads
// - broadcast/json framing utilities
// - onPublicKeyReceived, onSessionKeyReceived, onChatCipherReceived
// - integrate with Controller via listener/callback interfaces
```

```java
// Copilot: Implement MainController (JavaFX):
// - Bind buttons: StartServer/Connect/Disconnect/GenerateKeys/Load/Save/SendPubKey/QueryDirectory/SendChat/SendFile
// - Update UI labels (connection status, peer info)
// - For received chat: append both ciphertext (hex/base64) and decrypted plaintext to UI
```

---

## 7) 작업 우선순위
1) **순수 콘솔**로 네트워크/암호화 로직 프로토타입 → 단위 테스트
2) JavaFX에 이식(컨트롤러에서 서비스 호출, UI 바인딩)
3) 공개키 교환 → 세션키 교환 → 채팅 암호화 → 파일 암호화 전송
4) Directory Server 추가(간단 TCP-JSON)
5) README/Import 가이드, 스크린샷 & 시연 체크리스트

---

## 8) 빌드/실행 (Gradle 표준)
- `gradle init` (Application, Java 17+), JavaFX 플러그인/모듈 추가
- 실행: `./gradlew run` (Main.java)
- 패키징: `./gradlew jlink` 또는 `jpackage` (선택)

---

## 9) 데모 체크리스트
- [ ] 서버 시작(포트 표시), 클라이언트 접속(상태 갱신)
- [ ] 키 생성/저장/불러오기, 공개키 교환 로그
- [ ] 채팅 송신 → 상대 화면에 (암호문, 복호문) 모두 표시
- [ ] 파일 선택/전송 → 수신 저장 성공(무결성 OK)
- [ ] Directory Server로 이름 검색 → 공개키 획득 → 채팅/파일 동작 확인

---

## 10) 비고
- 예제 코드(슬라이드)는 Java 표준 라이브러리 기반 RSA/AES 데모이며, 실제 구현은 GCM/PEM 등으로 현대화.
- 수업 요구사항 충족이 1순위이므로, **GUI는 간결**, 기능은 **완전**하게.
