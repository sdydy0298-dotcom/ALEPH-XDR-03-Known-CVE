# ALEPH XDR-03 · 알려진 취약점 악용 탐지

**Log4Shell (CVE-2021-44228)** 및 **MITRE ATT&CK T1190** 웹 요청을 `block`, `alert`, `record`로 분류하는 독립형 보너스 과제입니다.

**공개 배포:** https://sdy-xdr-03.vercel.app

> 실제 Wazuh·운영 ZTNA 시스템 대신 **교육용 가상 경보 24건**과 **파일 기반 ZTNA 실습 판정기**로 재현합니다. Vercel 사이트는 정적 결과/실습 화면이며 실제 외부 IP를 차단하지 않습니다.

## 실행 및 검증

```bash
npm run xdr:run -- known-cve
npm test
npm run build
```

- 원본 경보: [ChoiTimo/aleph-defense-starter/xdr/fixtures/known-cve.json](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/xdr/fixtures/known-cve.json), **수정 없이 사용**
- 원본 공식 실행기: `scripts/xdr-run.mjs` (수정 없이 사용)
- 공식 결과 규격: `aleph.xdr.result.v1`
- 24건 자체 분석 결과: **BLOCK 8 / ALERT 8 / RECORD 8**, 정상 이벤트 오차단 0건
- `xdr/alerts.log`에 의심 경보 16줄 저장, `xdr/temporary-deny.json`에 15분 만료 임시 거부 규칙 8개 생성
- 기존 `ztna/rules.json` 정책을 그대로 읽고 `ztna/evaluate.mjs`에서 임시 정책과 함께 평가

## 제작 단계

| 제작 | 파일 | 검증 |
|---|---|---|
| 1 · 경보 읽기 | `xdr/known-cve/read-alerts.mjs` | 24건 → 24줄, 출발 IP·계정·시각·수준·설명만 추출하고 비밀 문자열 마스킹 |
| 2 · T1190 패턴 | `xdr/known-cve/patterns.json` | CVE-2021-44228 원격 조회·취약점 점검 흔적·정상 검색 근거 |
| 3 · 판단기 | `xdr/known-cve/decide.mjs` | import 없이 단독 실행, 확신도 >=0.85 BLOCK, >=0.50 ALERT |
| 4 · 알림/차단 | `xdr/known-cve/respond.mjs` | 명확한 공격만 차단 후보, 15분 만료, 기존 ZTNA 규칙 보존 |
| 5 · 시험 | `xdr/run.mjs`, `xdr/known-cve/result.json` | 공식 실행기·정상 오차단 검사·재현 가능한 로그 |
| 제출 | `.github/workflows/check.yml` | 자동 재실행·테스트·웹 빌드·결과 파일 일치 확인 |

`decide(alert)`는 JNDI 원격 조회 문자열을 **해석하거나 실행하지 않고 단순 비교**합니다. CVE 이름·JNDI 단어만 검색한 요청은 차단하지 않습니다. 실제 비밀키·비밀번호·쿠키는 사용·공개하지 않습니다.

이번 XDR-03 저장소는 [XDR-02](https://github.com/sdydy0298-dotcom/ALEPH-XDR-02-Web-Injection)와 별개이며, XDR-02의 기존 파일과 배포는 원래 상태로 복원했습니다.

**유의:** 비공개 심판 정답표는 제공되지 않아 8/8/8 수치가 실제 채점과 일치한다는 보장은 없습니다.
