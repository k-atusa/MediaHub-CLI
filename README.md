# MediaHub CLI

> **Zero-Knowledge, End-to-End Encrypted (E2EE) File Sharing & Real-Time Video Streaming CLI**  
> Written in Go, fully compatible with [MediaHub Desktop](https://github.com/k-atusa/MediaHub-desktop) and [MediaHub Web](https://github.com/k-atusa/mediahub).

MediaHub CLI는 고성능 Go 언어로 구현된 암호화 파일 공유 및 미디어 스트리밍 플랫폼의 공식 커맨드라인 인터페이스입니다. 데스크탑 GUI 없이도 터미널 환경, 원격 서버, SSH 세션에서 Zero-Trust 종단간 암호화(E2EE)를 통해 파일을 안전하게 보관하고 실시간으로 영상을 감상할 수 있습니다.

---

## 주요 기능 (Key Features)

- **Zero-Knowledge / E2EE 보안 아키텍처**:
  - 클라이언트 사이드 **Argon2id** (st: 256MB, t=3, p=6) 기반 KDF로 사용자 마스터 키 및 사용자 해시(`uHash`) 유도
  - 서버는 원본 비밀번호, 폴더명, 파일명, 파일 본문을 전혀 알 수 없는 제로 트러스트(Zero-Trust) 구조
- **강력한 대칭키 암호화 & 트래픽 분석 방지**:
  - **AES-256-GCM** 기반의 1MB 청크 단위 스트리밍 암호화 (`gcmx1`)
  - 파일 크기 추적 공격 방지를 위한 버킷 패딩(`Opsec.PadLen`) 자동 적용
- **실시간 암호화 영상 온디맨드 스트리밍 (`mediahub play` / `mediahub stream`)**:
  - 내장 로컬 복호화 HTTP 프록시 엔진을 통해 전체 파일을 다운로드받지 않고도 **HTTP Range 206 Partial Content**를 지원
  - **mpv, VLC, ffplay, IINA** 등 미디어 플레이어와 연동하여 즉각적인 시킹(seeking) 및 버퍼링 없는 비디오/오디오 스트리밍
- **플랫폼 간 호환 공유 토큰 (`mediahub share` / `mediahub import`)**:
  - 데스크탑 및 웹 버전과 100% 호환되는 패스워드 보호 폴더 공유 토큰 지원
  - 서버 메타데이터 손상 없이 안전하게 참조만 끊는 `unlink` 및 영구 삭제 `delete` 구분
- **편리한 CLI 사용자 경험**:
  - `mediahub login` 세션 자동 저장 (`~/.mediahub/config.json`)
  - 실시간 전송 속도 및 진행률 프로그레스 바 지원
  - 단축 명령어 지원 (`ls`, `mkdir`, `rmdir`, `put`, `get`, `rm`)

---

## 빌드 및 설치 (Build & Installation)

### 사전 요구사항
- [Go](https://go.dev/) 1.22 이상

### 직접 빌드
```bash
git clone https://github.com/k-atusa/MediaHub-CLI.git
cd MediaHub-CLI
go build -ldflags="-s -w" -trimpath -o mediahub .
```

### 크로스 컴파일 (Multi-Platform)
```bash
# macOS (Apple Silicon ARM64)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o mediahub-darwin-arm64 .

# macOS (Intel x86_64)
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o mediahub-darwin-amd64 .

# Linux (x86_64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o mediahub-linux-amd64 .

# Linux (ARM64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o mediahub-linux-arm64 .

# Windows (x86_64)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o mediahub-windows-amd64.exe .
```

---

## 사용법 (Usage Guide)

### 1. 로그인 및 세션 관리

```bash
# 대화형 로그인 (비밀번호 안전 마스킹 입력)
mediahub login

# 플래그를 통한 로그인 (사설 TLS 인증서 허용: -k)
mediahub login -s https://media.yourdomain.com:443 -u alice -p "YourPassword!" -k

# 현재 로그인 상태 및 연결 확인
mediahub status

# 서버 공지사항 조회
mediahub notice

# 세션 로그아웃
mediahub logout
```

### 2. 폴더 관리 (Folders)

```bash
# 내 폴더 목록 보기
mediahub ls
# 또는
mediahub folder list

# 새 폴더 생성
mediahub mkdir MyFolder
# 또는
mediahub folder create MyFolder

# 공유받은 폴더 연결 해제 (서버 데이터 유지, 내 목록에서만 제거)
mediahub folder unlink MyFolder

# 폴더 영구 삭제 (서버의 모든 암호화 파일 및 메타데이터 영구 삭제)
mediahub rmdir MyFolder
# 또는 확인 프롬프트 생략 (-y)
mediahub folder delete MyFolder -y
```

### 3. 파일 업로드 및 다운로드 (Files)

> 모든 파일 및 폴더 명령어는 이름뿐만 아니라 고유 식별자인 **PID**로도 직접 접근할 수 있습니다. (예: `mediahub ls <folderPid>`, `mediahub get <folderPid> <filePid>`)

```bash
# 특정 폴더의 파일 목록 보기
mediahub ls MyFolder
# 또는
mediahub file list MyFolder

# 단일 파일 암호화 업로드
mediahub upload MyFolder sample.mp4
# 또는 단축어
mediahub put MyFolder sample.mp4

# 여러 파일 및 디렉토리 일괄 업로드
mediahub upload MyFolder file1.png file2.pdf ./videos/

# 복호화된 파일 내용을 다운로드 없이 터미널 표준 출력(stdout)으로 확인
mediahub cat MyFolder notes.txt
# 또는 파이프라인 연계
mediahub cat MyFolder data.json | jq .

# 폴더 또는 파일의 암호화 상세 메타데이터 확인 (PID, 키, 패딩 길이 등)
mediahub info MyFolder
mediahub info MyFolder sample.mp4

# 파일 다운로드 및 복호화
mediahub download MyFolder sample.mp4
# 또는 저장 위치 지정
mediahub get MyFolder sample.mp4 -o ./downloads/saved.mp4

# 폴더 내 모든 파일 일괄 다운로드
mediahub download-all MyFolder --out ./all_files/

# 파일 삭제
mediahub delete MyFolder sample.mp4
# 또는 단축어
mediahub rm MyFolder sample.mp4

# 고아(orphan) 암호화 블록 정리
mediahub trim MyFolder
```

### 4. 실시간 암호화 비디오 스트리밍 & 플레이어 연동 (Streaming)

MediaHub CLI는 내장된 온디맨드 복호화 스트리밍 프록시를 통해 대용량 비디오도 즉시 감상할 수 있습니다.

```bash
# 1) 비디오 즉시 재생 (mpv, VLC, ffplay, IINA 등 자동 감지하여 실행)
mediahub play MyFolder movie.mp4

# 특정 플레이어를 지정하여 실행
mediahub play MyFolder movie.mp4 --player mpv
mediahub play MyFolder movie.mp4 --player vlc

# 플레이어를 띄우지 않고 로컬 스트리밍 URL만 생성
mediahub play MyFolder movie.mp4 --no-player

# 2) 폴더 전체에 대한 로컬 스트리밍 서버 가동
mediahub stream MyFolder --port 18080
```
- 스트리밍 서버가 켜지면 터미널에 생성된 `http://127.0.0.1:18080/stream/...` 주소를 복사하여 스마트폰, 브라우저, 외부 플레이어에 입력하면 실시간으로 재생 및 시킹이 가능합니다.

### 5. 암호화 폴더 공유 (Share & Import)

```bash
# 1) 폴더 공유 토큰 생성 (비밀번호로 암호화)
mediahub share MyFolder
# 또는 파일로 저장
mediahub folder share MyFolder --password "ShareSecretKey!" --out share_token.txt

# 2) 공유받은 사람이 토큰을 가져와 내 드라이브에 등록
mediahub import share_token.txt
# 또는 토큰 문자열 직접 전달
mediahub folder import "#START#..." --password "ShareSecretKey!"
```

---

## 아키텍처 및 내부 구조 (Architecture)

```
MediaHub-CLI/
├── cmd/               # Cobra 기반 CLI 명령어 구현체
│   ├── auth.go        # login, logout, status
│   ├── file.go        # upload, download, delete, trim, list
│   ├── folder.go      # create, delete, unlink, share, import
│   ├── play.go        # on-demand video streaming & player runner
│   ├── root.go        # 전역 옵션 및 클라이언트 초기화
│   └── ui.go          # ANSI 컬러, 진행률 바, 테이블 렌더러
├── pkg/
│   ├── bencode/       # Base64 분할 인코딩 및 NFC 정규화
│   ├── bencrypt/      # Argon2id, SHA3-256/512, AES-256-GCM, GCMx 스트리밍
│   ├── client/        # MediaHub REST API 및 Zero-Knowledge 클라이언트
│   ├── opsec/         # Opsec 헤더, Cfg 직렬화, 트래픽 난독화 패딩, 공유 토큰
│   └── proxy/         # Range 206 실시간 스트리밍 HTTP 프록시 엔진
├── test/
│   └── e2e_test.go    # 클라이언트, 프록시, 암호화 전 과정 E2E 테스트
└── main.go
```

---

## 라이선스 (License)

본 프로젝트는 MIT 라이선스에 따라 배포됩니다. 자세한 사항은 [LICENSE](LICENSE) 파일을 참조하십시오.
