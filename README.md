# bytenode-account

bytenode 통합 계정 SSO / OAuth 2.0 서버. bytenode · byteexam · bytetext · bytewrite가 하나의 bytenode 계정으로 로그인합니다. 계정 DB는 bytenode109가 소유하고, 이 서버는 로그인/가입 UI, API 프록시, OAuth 인가 코드 발급을 담당합니다. 상태 없는 설계라 Vercel 서버리스에서 그대로 동작합니다.

배포: https://bytenode-account.vercel.app

## 페이지

- `/login` — 로그인
- `/welcome` — 회원가입
- `/developer` — OAuth 설정/연동 문서
- `/terms`, `/privacy` — 이용약관 · 개인정보처리방침

## 연동 방법

`/developer` 페이지 참고. 요약:

- 간단 SSO: `/login?redirect=<돌아갈 주소>` → 완료 후 `#bn_token=<JWT>` 붙여 복귀
- OAuth 2.0: `GET /authorize` → `POST /token` → `GET /userinfo`

## 환경변수

- `SSO_SECRET` (필수) — OAuth 인가 코드 서명용 시크릿
- `BN_API` — 계정 원본 서버 (기본 `https://bytenode109.vercel.app`)
- `EXTRA_ORIGINS` — redirect origin 추가, 형식 `client_id|https://도메인,client_id|https://도메인2`

## 실행

```powershell
npm install
npm start   # http://localhost:5170
```
