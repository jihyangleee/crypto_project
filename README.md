# Crypto Project 
- 암호화된 메시지와 파일을 server에게 전달하고 server가 그것을 복호화하여 평문을 얻는 프로젝트이다.

[요구사항]
1. server 와 client 간에 메시지를 주고 받을 수 있어야 한다.
2. server 와 client 간에 파일을 주고 받을 수 있어야 한다.
3. 암호화된 메시지를 줄 수 있고 리시버는 그것을 복호화 한다.
4. 암호화된 파일을 보낼 수 있고 리시버는 그것을 복호화 한다.
5. 그 파일의 RSA 서명을 보내고 리시버는 그 서명을 인증한다.
6. 한 파일에 대한 암호화와 서명인증을 함께 전달한다. 리시버는 그것을 복호화하고 서명을 인증한다.

- 프로그램 작동법
 한 컴퓨터 내에서 서로 다른 터미널에 아래와 같은 명령어를 작성하면
 두개의 창이 뜬다.</br>
 (자세한 작동방법과 이용방법은 영상으로도 확인가능하다.-> https://youtu.be/OG8s7jI_9co)</br>
 IDE는 VSCODE에서 실행했으며 깃헙에 올라와있는 폴더를 다운받아 사용하면 된다.</br>
```git clone https://github.com/jihyangleee/crypto_project.git
cd crypto_project/demo
./gradlew build        
./gradlew runSecureUI  
```
---
### 프로그램 기본 설명

<img width="1280" height="462" alt="image" src="https://github.com/user-attachments/assets/96cf4529-a477-42c5-9aef-b6d93e1fb159" />
<img width="895" height="467" alt="image" src="https://github.com/user-attachments/assets/fba6a040-7055-42fa-81ca-5865347456d7" />

> 처음에는 두 개의 화면을 모니터에 띄운다. 그 뒤에는 하나는 client 그리고 다른 하나는 server로 설정한다.
  둘을 연결하기 전에 각각 public key와 private key를 만든다.
  server 측에서 connect 버튼을 누르면 wait 상태(노란색)으로 가고 client에서 connect를 요청하면 서로 연결된 상태(초록색)가 된다.
  연결 상태가 되면 둘은 public key를 서로 주고 받는다.

<img width="890" height="364" alt="image" src="https://github.com/user-attachments/assets/7a190259-7a1c-4dac-84e9-11e2ae4bfa31" />

> 표시된 화면에서 Encrypt with AES 와 Sign plaintext with private key 부분에 체크표시가 있음을 알 수 있다.
  그것을 해제하면 HELLO 라는 메시지를 평문 그대로 보내고 서버에서 평문을 받는다.
  
<img width="888" height="509" alt="image" src="https://github.com/user-attachments/assets/3ece24dd-d314-4de2-9f31-d20015fab7fc" />

> 암호화 기능과 서명인증 기능에 동의를 한 경우에는 아래의 이미지와 같이 서버에서 AES로 암호화된 암호문과 RSA 암호화(서버의 공개키)된 AES키와 서명인증하는 암호문을 클라이언트로부터 받을 수 있다. 
  Decrypt 를 누르면 서버의 개인키로 복호화하여 AES키를 얻고 그것을 바탕으로 암호문을 복호화 한다.
  이때 서버에서 이미 서명인증과정도 같이 해주어 status : verified가 같이 나타난다.

<img width="893" height="509" alt="image" src="https://github.com/user-attachments/assets/39b0529f-bb9c-4074-819f-a5c7fd33ad76" />

> 그 뒤에 ui 에서도 수동으로 signautre verification을 수행해주어 한번 더 검증해준다.

<img width="894" height="510" alt="image" src="https://github.com/user-attachments/assets/848e8c81-ed11-4d1b-9269-9e4a4c4aae4d" />

> 이번에는 파일을 평문으로 주고받는 과정이다.

<img width="892" height="515" alt="image" src="https://github.com/user-attachments/assets/575a2ca5-87dd-4870-931b-ac892fd5c120" />

> AES로 암호화 한 암호문, RSA로 암호화된 AES 키, 서명 인증 암호문을 서버가 받고 그것을 토대로 복호화한다. (전체적인 암호 및 복호화 흐름은 따로 정리할 것이다.)
  암호화된 메시지를 받았을 때와 마찬가지로 ui에서 수동으로 signature verification을 수행한다.

<img width="509" height="271" alt="image" src="https://github.com/user-attachments/assets/f0c9551f-28a7-4359-9bda-3a7c636a647a" />

> log를 통해 어떻게 암호문이 서버에서 처리되는 지 알 수 있다. 

---
### [사용된 암호 알고리즘]
- RSA (공개키와 개인키), AES(대칭키), SHA(해시 함수)
  1. 평문으로 된 메시지와 파일을 AES 대칭키를 이용해 암호화 한다. 
  2. 이를 서버에 보낼 때 AES 대칭키도 같이 보내야 하는데 이것을 그냥 보내게 되면 해커에게 노출되기 쉽다
     -> AES를 RSA 서버의 공개키를 이용하여 암호화를 해서 서버에게 보낸다.
  3. 이때 서명인증을 하기 위해 (특정 클라이언트가 보냈다는 것을 증명하기 위함) 보내는 평문의 해시값을 얻는다.
  4. 해시값에 클라이언트의 private key를 이용해 암호화하여 자신이 이 메시지 혹은 파일을 보내는 주체임을 서버에게 알려준다.
  5. 서버는 특정 클라이언트로부터 암호문, RSA 로 암호화된 대칭키, 서명인증 암호문을 받는다.
  6. 그 뒤 자신의 개인키로 대칭키를 복호화하고 그 대칭키를 활용해 암호문을 복호화한다.
  7. 디지털 서명은 클라이언트의 공개키로 해시값을 얻어내고 현재 복호화된 암호문을 해시함수로 계산하여 두 개의 해시값을 비교한다.







