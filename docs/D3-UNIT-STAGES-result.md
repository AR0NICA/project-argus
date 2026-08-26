# D3-UNIT-STAGES — R0-UNIT 런타임 결과

> **템플릿 — 미작성 (NOT YET FILLED).** 이 문서는 실제 라이브 BASE R0-UNIT 런타임 실행과
> 독립 교차검토가 완료된 **이후에** 채워야 합니다. 모든 `<...>` 자리표시자는 실제 값으로
> 교체하기 전까지 그대로 둡니다. 가짜 값(계정 id, ARN, 엔드포인트, CIDR, run id 등)을
> 미리 채워 넣지 않습니다.

Status: **<PASS/FAIL — 판정 대기>** · Date: `<YYYY-MM-DD>` · Environment: BASE · Goal: S01-S10 unit-stage chain proof (`proof_kind=runtime`)

Gate references: D1 `CRR-D1-BASE-R06-2026-08-20` (완료) · D2 kill-switch `6/6` composite PASS
(`CRR-D2-BASE-R2-R3-2026-08-24`, 완료) · D3 `<CRR-D3-...>` (본 결과가 기록해야 할 대상).

D3 close-out은 다음 두 조건이 **모두** 충족되어야 성립합니다:

1. 증적이 `proof_kind=runtime`이어야 함 (`proof_kind=local_synthetic`은 계약/핸드오프/가드
   증명일 뿐 D3 완료로 인정되지 않음).
2. 독립 교차검토 결과가 `CrossReviewRef`로 기록되어야 함 (`<CRR-D3-...>`).

이 두 조건 중 하나라도 비어 있으면 이 문서는 PASS로 표시될 수 없습니다.

## 판정 요약

- **기술 판정**: `<PASS / FAIL / PENDING>`
- **방법**: run id `<RUN_ID>` 기준으로 라이브 BASE에서 S01-S10 각 스테이지를 최소 1회
  실행. `runner/collect_d3_runtime.py`로 관찰된 토큰/핸드오프 + 스테이지별 독립 소스
  원시증적을 조립하고, `runner/run_d3_gate.py --require-runtime`으로 게이트 판정.
- **핵심 불변식**: 각 스테이지의 **고정 성공 토큰**과 **다음 스테이지 핸드오프**가 실제로
  산출되었고, 동일한 `run_id`와 **직전 스테이지 토큰**에 바인딩되어 있음을 확인. 핸드오프는
  1회용·TTL 120초·run 바인딩이며, 재사용/위조/만료/다른 run 사용/잘못된 종류/잘못된
  소비 스테이지는 모두 거부됨.
- **공격 실행 범위**: S01 ≤ 12 요청; S02-S10은 스테이지당 계약 요청 1 + 컨트롤 요청 1;
  ≤ 1 rps, concurrency 1, 요청 간 ≥ 1초; synthetic 결과만, ≤ 10 rows / ≤ 32 KiB; 허용된
  고정 액션은 `MARKER`(S04) / `IMDS_IDENTITY`(S05) / `WAS_AUTH`(S08)뿐이며 임의 SQL/셸/URL/
  파일 경로 없음; S07은 정확한 key+version `GetObject`만이며 `ListBucket`/write/delete/정책
  변경 없음.
- **D5 경계**: HybridNB는 `disabled_not_evaluated`로 유지됨. 모델 스코어/라벨/임계값이
  판정 이전에 산출되지 않았으며, WAF와 HybridNB 입력은 서로 독립적인 원본에서만 파생됨
  (D5-DUAL-DETECTION 이전에는 fusion 없음). 본 D3 결과는 D5 4분면 평가에 영향을 주지 않음.

## 정제(sanitization) 안내

이 문서는 정제된 요약입니다. 원시 증적(리소스 id, 엔드포인트, CIDR, ARN, SSM 커맨드 id,
`native_record_id`, 해시 원본 파일 등)은 로컬의 git-ignored 증적 루트
`evidence/<RUN_ID>/raw/`에만 보관되며, Notion·GitHub 등 외부에는 raw/secret/id를
복사하지 않습니다. 이 문서에는 정제된 판정과 상태만 기록합니다.

## 스테이지별 결과 표 (S01-S10)

각 행은 라이브 BASE 실행에서 실제로 관찰된 값으로 채웁니다. "고정 성공 토큰"과
"다음 핸드오프"는 값 자체가 아니라 **산출/검증 여부**(및 필요 시 해시 접두부 등 정제된
식별자)만 기록합니다.

| Stage | 고정 성공 토큰 | 다음 핸드오프 | 독립 소스 원시증적 | 결과 |
|-------|----------------|----------------|----------------------|------|
| S01 | `endpoint_map_hash` — `<산출 여부>` | `endpoint_contract_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S02 | `auth_decision_hash` — `<산출 여부>` | `auth_decision_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S03 | `admin_session_hash` — `<산출 여부>` | `upload_ticket_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S04 | `web_marker_sha256` — `<산출 여부>` | `web_action_context_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S05 | `role_identity_hash` — `<산출 여부>` | `credential_handoff_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S06 | `external_identity_event_id` — `<산출 여부>` | `same_role_session_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S07 | `canary_object_sha256` — `<산출 여부>` | `was_bundle_handoff_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S08 | `was_admin_session_hash` — `<산출 여부>` | `db_read_ticket_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S09 | `db_result_manifest_id` — `<산출 여부>` | `result_handle_id` — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |
| S10 | `delivery_sha256` — `<산출 여부>` | full-run evidence manifest — `<산출 여부>` | `<독립 소스 종류 + native_record_id>` | `<PASS/FAIL>` |

## 안전 경계 확인 체크리스트

도구(`run_d3_gate.py`, `scripts/validate_d3_evidence.py`)가 자동 검증하는 항목과, 검토자가
**수동으로** 재확인해야 하는 항목을 구분합니다. `[수동 확인]` 표시가 있는 네 항목은
자동 검증 대상이 아니므로 검토자가 직접 확인하고 서명해야 합니다.

- [ ] S01 총 요청 수 ≤ 12 (validator 자동 검증 대상 — S01 이벤트의 `request_count`를 `guard_s01_requests`가 검사)
- [ ] 스테이지당 이벤트 수가 계약대로임 — S02는 2건(계약 이벤트 + 고정 HybridNB 어댑터), 나머지는 1건 (validator 자동 검증 대상). 단, "계약 요청 vs 컨트롤 요청"의 의미 구분은 자동 검증하지 않으므로 검토자가 확인 `[수동 확인]`
- [ ] ≤ 1 rps, concurrency 1, 요청 간 ≥ 1초 유지 (게이트 자동 검증 대상)
- [ ] synthetic 결과만 사용, ≤ 10 rows / ≤ 32 KiB (S09/S10에서 반환 전 확인, 게이트 자동 검증 대상)
- [ ] 허용된 고정 액션(`MARKER`/`IMDS_IDENTITY`/`WAS_AUTH`)만 사용, 임의 SQL/셸/URL/파일 경로 없음 (게이트 자동 검증 대상)
- [ ] S07이 정확한 key+version `GetObject`만 수행, `ListBucket`/write/delete/정책 변경 없음 (게이트 자동 검증 대상)
- [ ] 크리덴셜 자료 미포함, 모든 증적 레코드가 `secret_material_present=false` (validator 자동 검증 대상)
- [ ] 런타임 S02에서 HybridNB가 `disabled_not_evaluated`로 유지됨 (스코어/라벨/임계값 없음) — validator 자동 검증 대상(`assert_hybridnb_frozen` + S02 어댑터 필수)
- [ ] `CrossReviewReference`(`<CRR-D3-...>`)의 진위 확인 — 실제 검토자가 실제로 검토했는지 `[수동 확인]`

## 독립 교차검토 체크리스트

검토자는 스테이지 구현자와 달라야 하며(자기 스테이지 자기 승인 금지), 아래 항목을
스테이지별로 각각 확인합니다.

- [ ] 각 스테이지의 고정 성공 토큰이 실제로 산출되었음을 확인
- [ ] 각 스테이지의 1회용 TTL(120초)·run 바인딩 핸드오프가 다음 스테이지에서 정확히
      소비되었음을 확인 (재사용/위조/만료/타 run 사용/잘못된 종류/잘못된 소비 스테이지가
      아님)
- [ ] 각 스테이지에서 harness가 주입한 선행 토큰인지, 실제 선행 스테이지 토큰인지 구분하여
      기록 (주입된 경우 golden chain 자격이 없음을 재확인)
- [ ] 각 스테이지의 독립 소스 원시증적이 다음을 모두 만족하는지 확인:
  - [ ] 소스 고유 형태 유지 (CloudTrail/S3는 원본 `eventID` 포함 JSON, Flow Log는 원본
        버전 행, ALB access는 원본 access-log 행, auditd는 `audit(epoch:serial)` id,
        Nginx/ModSecurity는 타임스탬프 포함 JSON export, RDS audit/general은
        `ARGUS-Q01`을 포함한 타임스탬프 행)
  - [ ] web/was 애플리케이션 로그가 아닌 독립 소스인지 확인
  - [ ] 해시(SHA-256) 일치 확인
  - [ ] 각 파일 ≤ 1 MiB
  - [ ] 시크릿성 자료 없음 (validator 스캔 결과와 대조)
- [ ] 원시증적이 teardown **이전에** `evidence/<RUN_ID>/raw/`에 캡처되었음을 확인
- [ ] 이 실행의 `proof_kind=runtime`이고 `golden_chain=false`(또는
      `counts_toward_golden_chain=false`)로 표시되어 있음을 확인
- [ ] 스테이지 구현자가 자신이 구현한 스테이지를 스스로 승인하지 않았음을 확인

교차검토 결과: `<CRR-D3-...>` — 검토자 `<이름>` · 검토일 `<YYYY-MM-DD>`.

## 사후 상태 및 teardown

- `<RUN_ID>` 실행 종료 후 워크로드/RDS/BASE 스택 상태: `<PENDING>`
- `terraform plan` 결과(변경 없음 여부): `<PENDING>`
- 교차검토(`CrossReviewRef` 기록) 완료 **이전에는** 증적 정리(evidence cleanup)나
  teardown을 진행하지 않습니다.
- 교차검토 완료 후에만 `infra/README.md`에 정의된 순서로 가드된 teardown 스크립트를
  실행합니다: evidence → ECR → Image Builder → destroy → backend. 각 단계는
  `CrossReviewReference`와 `-Execute` 플래그를 명시적으로 요구합니다.
- teardown 이후 상태 확인(빈 state, 활성 BASE 리소스 없음 등): `<PENDING>`

## 구현 기준점

- GitHub commit: `<commit-sha>` (D3 unit-stage 계약/러너/게이트 구현)
- GitHub commit: `<commit-sha>` (라이브 BASE R0-UNIT 런타임 실행 반영, 있는 경우)
- 관련 문서: `docs/D3-UNIT-CONTRACT.md`, `docs/D3-REDEPLOY-RUNBOOK.md`
- 선행 결과 문서: `docs/D1-...-result.md`(있는 경우), `docs/D2-SAFETY-result.md`
- Notion 링크: `<Notion 페이지 URL>`
