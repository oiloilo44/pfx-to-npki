# PFX to NPKI Converter

PFX/P12 인증서 파일을 NPKI 폴더 구조(`signCert.der`, `signPri.key`)로 변환하는 Windows용 Python 도구입니다.

## 기능

- PFX/P12 파일 로드
- OpenSSL 기반 VID 후보 추출
- NPKI 표준 폴더 구조 생성
- `signCert.der`, `signPri.key` 출력
- 비밀번호 마스킹 입력

## 주의

- 실제 인증서, 개인키, 비밀번호는 저장소에 포함하지 않습니다.
- 변환 결과물인 `NPKI/` 폴더도 커밋하지 않습니다.
- 본인 소유 인증서의 백업/호환성 확인 용도로만 사용하세요.

## 실행

```bash
pip install cryptography pypinksign
python convert_pfx_to_npki.py
```

스크립트를 실행하면 PFX 파일 경로와 비밀번호를 입력받고, 같은 위치에 `NPKI` 폴더를 생성합니다.

## 구조

```text
convert_pfx_to_npki.py  변환 스크립트
openssl_bin/            VID 확인에 사용하는 Windows OpenSSL 실행 파일
```
