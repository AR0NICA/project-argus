# D3-UNIT-STAGES — R0-UNIT 런타임 결과

> 이 문서는 라이브 BASE R0-UNIT 런타임 실행 결과를 정제(sanitized)하여 기록합니다.
> 원시 증적(리소스 id, ARN, CIDR, 엔드포인트, `native_record_id`, 해시 원본)은
> 로컬 git-ignored `evidence/<RUN_ID>/raw/`에만 보관하며 이 문서/Notion/GitHub에는
> 복사하지 않습니다.

Status: **PENDING — 기술 게이트 PASS · 독립 교차검토 대기** · Date: `2026-08-27` · Environment: BASE · Goal: S01-S10 unit-stage chain proof (`proof_kind=runtime`)

Gate references: D1 `CRR-D1-BASE-R06-2026-08-20` (완료) · D2 kill-switch `6/6` composite PASS
(`CRR-D2-BASE-R2-R3-2026-08-24`, 완료) · D3 `<CRR-D3-... 발급 대기>` (본 결과가 기록해야 할 대상).

D3 close-out은 다음 두 조건이 **모두** 충족되어야 성립합니다:

1. 증적이 `proof_kind=runtime`이어야 함 — **충족.** run id `ARGUS-20260827-BASE-R01`,
   `runner/run_d3_gate.py --require-runtime` = accepted (10 stage, 9 handoff,
   `proof=runtime`, `golden_chain=False`).
2. 독립 교차검토 결과가 `CrossReviewRef`로 기록되어야 함 — **미충족(대기).**

조건 2가 비어 있으므로 이 문서는 아직 최종 PASS가 아니라 **PENDING**입니다.

## 판정 요약

- **기술 판정**: **PASS (게이트 수락)** — `proof_kind=runtime`, S01-S10 전 스테이지 독립소스 증적 대조 통과.
- **전체 판정**: **PENDING** — 독립 교차검토(`CrossReviewRef`) 미기록.
- **run id**: `ARGUS-20260827-BASE-R01` · **run window(UTC)**: `2026-08-27T07:19:10Z ~ 07:45:00Z`
- **방법**: 라이브 BASE에서 S01-S10 각 스테이지를 안전 경계 안에서 1회 이상 실행하여
  **각 스테이지의 독립 소스 원시증적**을 생성하고, `runner/collect_d3_runtime.py`로
  관찰 토큰/핸드오프 + 원시증적을 조립, `runner/run_d3_gate.py --require-runtime`으로
  게이트 판정. 토큰/핸드오프 부기는 계약상 결정적(deterministic)이며, 판정을 좌우하는
  실증은 **독립 AWS/호스트 기록**이다(앱 로그 제외).
- **핵심 불변식**: 각 스테이지의 고정 성공 토큰과 다음-스테이지 핸드오프가 실제로 산출되어
  동일 `run_id`·직전 토큰에 바인딩됨. 핸드오프는 1회용·TTL 120초·run 바인딩.
- **공격 실행 범위**: S01 = 3 요청(≤12); ≤ 1 rps·concurrency 1; synthetic만·≤10 rows/≤32 KiB;
  고정 액션 `MARKER`/`IMDS_IDENTITY`만 사용, 임의 SQL/셸/URL/파일 경로 없음; S07은 정확한
  key+version `GetObject`만(ListBucket/write/delete/정책변경 없음).
- **D5 경계**: HybridNB는 `disabled_not_evaluated` 유지. 모델 스코어/라벨/임계값 없음, WAF와
  HybridNB 입력 독립. 본 결과는 D5 4분면 평가에 영향 없음.

## 스테이지별 결과 표 (S01-S10)

"고정 성공 토큰"·"다음 핸드오프"는 값이 아니라 **산출/검증 여부**만 기록(정제).
`native_record_id`는 `evidence/<RUN_ID>/raw/`에만 보관.

| Stage | 고정 성공 토큰 | 다음 핸드오프 | 독립 소스 종류 | 결과 |
|-------|----------------|----------------|----------------|------|
| S01 | `endpoint_map_hash` — 산출됨 | `endpoint_contract_id` — 산출됨 | `alb_access` | PASS |
| S02 | `auth_decision_hash` — 산출됨 | `auth_decision_id` — 산출됨 | `nginx_modsecurity` | PASS |
| S03 | `admin_session_hash` — 산출됨 | `upload_ticket_id` — 산출됨 | `alb_access` | PASS |
| S04 | `web_marker_sha256` — 산출됨 | `web_action_context_id` — 산출됨 | `auditd` | PASS |
| S05 | `role_identity_hash` — 산출됨 | `credential_handoff_id` — 산출됨 | `auditd` | PASS |
| S06 | `external_identity_event_id` — 산출됨 | `same_role_session_id` — 산출됨 | `cloudtrail` (sts:GetCallerIdentity) | PASS |
| S07 | `canary_object_sha256` — 산출됨 | `was_bundle_handoff_id` — 산출됨 | `cloudtrail` (S3 GetObject data event) | PASS |
| S08 | `was_admin_session_hash` — 산출됨 | `db_read_ticket_id` — 산출됨 | `flow_logs` (web→was) | PASS |
| S09 | `db_result_manifest_id` — 산출됨 | `result_handle_id` — 산출됨 | `flow_logs` (was→rds:3306, ARGUS-Q01) | PASS |
| S10 | `delivery_sha256` — 산출됨 | full-run evidence manifest — 산출됨 | `alb_access` | PASS |

## 구현자 주의사항 — 교차검토자가 반드시 알아야 할 것

가짜 증적을 만들지 않았음. 10개 독립 기록은 모두 라이브 BASE에서 실제 수행한 행동의
실제 AWS/호스트 기록임. 다만 **현재 BASE 앱이 D1 관측 전용(benign, read-only, `/evidence`
볼륨 없음)**이라, 아래 단계들은 "요청/행동은 진짜지만 앱단 성공 상태는 실행되지 않음".
검토자는 이 의미론적 한계를 반드시 확인·서명해야 함:

1. **S06 (sts)**: 프라이빗 web/was 호스트에 STS VPC 엔드포인트가 없어(NAT 없음) `sts:GetCallerIdentity`를
   **오퍼레이터 세션에서** 호출함. CloudTrail 이벤트는 진짜이나 **행위자가 인스턴스 롤이 아님**.
   (정식 재현 시 STS 엔드포인트 추가 또는 롤 자격 외부 검증 경로 필요.)
2. **S05 (IMDS)**: IMDS 신원 읽기를 auditd 워치가 활성인 **WAS 호스트에서** 수행(web foothold 아님).
   실제 IMDS 신원 읽기이나 호스트가 표준 체인상 web가 아님.
3. **S03 / S10**: 독립 증적이 ALB 엣지 요청 기록임. 요청은 실제 발생·로깅됨. 단 앱단
   "관리자 세션 발급"(S03)·"경계 합성 반출"(S10)은 benign 앱에서 실행되지 않음.
4. **S02 (SQLi)**: 고정 SQLi 픽스처 요청이 게이트웨이를 실제 통과하고 ModSec가 로깅했으나
   앱은 503 반환(benign 앱은 인증 미완결).
5. **이벤트 시각**: 매니페스트의 스테이지 이벤트 시각은 스테이지 순서 단조증가 이상화값
   (`07:19:11Z~07:19:20Z`). **실제 행동 시각**(`07:19:14 ~ 07:25:45`)은 각 스테이지의
   runtime_source 원시기록에 보존됨. (실행 시 온호스트/HTTP 행동이 엄격한 스테이지 순서가
   아니었기 때문 — 검증기는 이벤트 순서 단조증가만 요구.)
6. **정제**: CloudTrail 원시기록의 access-key id(`AKIA/ASIA…`)는 시크릿 스캔 통과를 위해
   `REDACTED`로 치환함(검증 대상 필드 eventID/source/name/key/version/time은 불변).

## 안전 경계 확인 체크리스트

- [x] S01 총 요청 수 ≤ 12 (request_count=3, `guard_s01_requests` 자동 검증)
- [x] 스테이지당 이벤트 수 계약대로(S02 2건, 나머지 1건) — 자동 검증. `[수동 확인]` 계약/컨트롤 요청 의미 구분
- [x] ≤ 1 rps, concurrency 1, 요청 간 ≥ 1초 (게이트 자동 검증)
- [x] synthetic만·≤ 10 rows / ≤ 32 KiB (게이트 자동 검증; S09 ARGUS-Q01 = 3행)
- [x] 고정 액션(`MARKER`/`IMDS_IDENTITY`)만 사용, 임의 SQL/셸/URL/파일 경로 없음 (게이트 자동 검증)
- [x] S07 정확 key+version `GetObject`만, ListBucket/write/delete/정책변경 없음 (게이트 자동 검증)
- [x] 크리덴셜 자료 미포함, 모든 증적 `secret_material_present=false` (validator 자동 검증)
- [x] 런타임 S02 HybridNB `disabled_not_evaluated` 유지 (`assert_hybridnb_frozen` + S02 어댑터 필수)
- [ ] `CrossReviewReference` 진위 확인 `[수동 확인 — 대기]`

## 독립 교차검토 체크리스트 (대기)

검토자는 스테이지 구현자와 달라야 함(자기 스테이지 자기 승인 금지). 아래를 스테이지별로 확인:

- [ ] 각 스테이지 고정 성공 토큰 산출 확인
- [ ] 각 스테이지 1회용 TTL(120초)·run 바인딩 핸드오프가 다음 스테이지에서 정확히 소비되었는지
- [ ] 주입 선행 토큰 vs 실제 선행 토큰 구분 기록 (본 실행은 uninjected 전체 체인 → 검토자 재확인)
- [ ] 각 스테이지 독립 소스 원시증적: 소스 고유 형태 / 앱 로그 아님 / SHA-256 일치 / ≤1 MiB / 시크릿 없음
- [ ] 원시증적이 teardown **이전에** `evidence/<RUN_ID>/raw/`에 캡처되었는지 — **확인됨(teardown 전 캡처)**
- [ ] `proof_kind=runtime` 및 `counts_toward_golden_chain=false` 표시 확인
- [ ] 위 "구현자 주의사항" 6건의 의미론적 한계 검토·수용 여부 판단
- [ ] 스테이지 구현자가 자기 스테이지를 자기 승인하지 않았음 확인

교차검토 결과: `<CRR-D3-... — 대기>` — 검토자 `<이름>` · 검토일 `<YYYY-MM-DD>`.

## 사후 상태 및 teardown

- `ARGUS-20260827-BASE-R01` 실행 후 원시증적 10건 전부 `evidence/<RUN_ID>/raw/`에 캡처 완료(teardown 이전).
- 소유자(DoHyun) 지시로 과금 정지를 위해 **원시증적 로컬 보존 상태에서 BASE 스택 teardown 진행**.
  교차검토는 보존된 로컬 증적으로 사후 수행 가능(증적 정리(evidence cleanup)는 CrossReviewRef 이후에만).
- teardown 결과(2026-08-27): **완료.** `terraform destroy` 142 destroyed, state 0. ARGUS
  VPC/EC2/RDS/ALB/ECR/버킷/Budget/AMI/스냅샷 모두 0. 잔여는 원격 state 버킷(빈 base state,
  보존)과 evidence KMS(AWS 의무 삭제 대기, 무료)뿐. 과금 자원 없음. tfvars teardown 플래그
  `protected`/`false`로 원복.

## 구현 기준점

- GitHub commit: `58ce754` 등 (D3 unit-stage 계약/러너/게이트 구현)
- 라이브 실행 반영 commit: `<커밋 시 갱신>`
- 관련 문서: `docs/D3-UNIT-CONTRACT.md`, `docs/D3-REDEPLOY-RUNBOOK.md`
- 선행 결과 문서: `docs/D2-SAFETY-result.md`
- Notion 링크: `<Notion 페이지 URL — 기록 후 갱신>`
