> **환경:** `BASE`
> **관련 목표:** `G1`
> **관련 실행 ID:** `D0-SCOPE`, `D0A-LOCAL`, `D1-OBSERVABILITY`, `D2-SAFETY`, `D3-UNIT-STAGES`, `D4-FULL-CHAIN`, `D5-DUAL-DETECTION`
> **작업 영역:** 인프라, 관측·증적, 공격 체인
> **선행 설계:** <mention-page url="https://app.notion.com/p/3b4f118fd3928192a7c4fe6ff42458d5"/> · <mention-page url="https://app.notion.com/p/3adf118fd39280d08462c7aca850a1af"/> · <mention-page url="https://app.notion.com/p/3adf118fd3928001993acdf23bf0c56c"/>

## 1. 목적과 비목적

이 워크북은 승인된 격리 실습 계정에서 Project ARGUS의 `BASE` AWS 3계층 환경을 Terraform으로 재현하기 위한 작업 단위다. 목표는 **환경 -> 관측 -> 단계별 공격 계약** 순서로, S01~S10이 소비할 고정 경계와 증적 기반을 먼저 만든 뒤 BASE 전체 체인을 재현 가능하게 하는 것이다.

다음은 이 문서의 목적이 아니다.

- 새 아키텍처, 공격 체인, 취약점 또는 탐지 정책을 재설계하지 않는다.
- 인터넷 공개 서버, 공인 EC2/RDS, NAT Gateway, 광범위 IAM, 실제 사용자 데이터, 자격증명 원문을 만들지 않는다.
- 실제 공격 페이로드, 범용 셸, C2, 임의 스캔, 쓰기/삭제 API를 구현하거나 기록하지 않는다.
- `terraform plan` 또는 문서 검토를 AWS 런타임 증명으로 주장하지 않는다.

### 고정 D0 결정: HybridNB 경계

`D0`부터 `D4` 전까지 Core가 보장하는 것은 **버전이 있는 독립 HybridNB request-envelope 인터페이스와 이벤트 스키마**뿐이다. 모델 아티팩트, 전처리, 추론 서비스, 임계값, WAF/HybridNB 4분면 평가는 `D5-DUAL-DETECTION`에서만 구현·동결·검증한다.

- Nginx request tap은 승인된 요청에서 불변 `request_envelope`을 만들고 WAF용 원시 트랜잭션과 HybridNB용 독립 envelope를 함께 기록한다.
- `D0A-LOCAL`, BASE IaC, `D1-OBSERVABILITY`, S02~S04는 모델 존재나 모델 결과를 기다리지 않는다. D5 전 evidence event는 envelope version과 `evaluation_status=disabled_not_evaluated`를 기록할 수 있으며, 승인·차단 결정을 바꾸지 않는다.
- WAF와 HybridNB의 입력은 반드시 독립 원본에서 파생한다. CRS rule ID, anomaly score, WAF action은 HybridNB 특성에 넣지 않으며, ML score/label은 WAF 규칙 입력이 아니다. 결합은 D5의 policy/fusion 계층에서만 한다.

## 2. D0 전제조건과 게이트

### 2.1 D0-SCOPE 동결표

아래 값을 `terraform.tfvars`에 비밀 없이 기록하고, 변경 시 승인자·사유·회귀 결과를 실행 manifest에 남긴다.

<table fit-page-width="true" header-row="true">
	<tr>
		<td>동결 항목</td>
		<td>기준값 또는 계약</td>
		<td>확인</td>
	</tr>
	<tr>
		<td>AWS 계정, 리전, AZ ID</td>
		<td>`ap-northeast-2` 권장. 계정별 AZ ID를 기록하고 AZ 이름만 신뢰하지 않음</td>
		<td>TODO: account ID, final region, AZ IDs</td>
	</tr>
	<tr>
		<td>VPC</td>
		<td>`10.20.0.0/16`</td>
		<td>고정</td>
	</tr>
	<tr>
		<td>태그</td>
		<td>`Project=ARGUS`, `Environment=BASE`, `ManagedBy=IaC`</td>
		<td>고정</td>
	</tr>
	<tr>
		<td>허용 단말</td>
		<td>승인 시험 CIDR만 ALB `443/TCP` 접근</td>
		<td>TODO: approved CIDR</td>
	</tr>
	<tr>
		<td>앱/AMI/포트</td>
		<td>AMI/image SHA-256, TLS 인증서, ALB->Web 앱 포트를 동결</td>
		<td>TODO: approved AMI/image, certificate ARN, final app port</td>
	</tr>
	<tr>
		<td>체인 입력</td>
		<td>`ATK-*`/`BEN-*` fixture ID와 비공개 원문 hash, `ARGUS-Q01`</td>
		<td>fixture 원문은 저장소 미포함</td>
	</tr>
	<tr>
		<td>데이터/속도</td>
		<td>합성 결과 최대 10행 및 32 KiB, `1 rps`, concurrency `1`</td>
		<td>S09와 S10에서 이중 검사</td>
	</tr>
	<tr>
		<td>비용/중지</td>
		<td>비용 상한, Budget alarm, 담당자, 허용 시간, kill switch 담당자</td>
		<td>TODO: threshold, owner, time window</td>
	</tr>
</table>

### 2.2 D0A-LOCAL: 모델 비차단 앱 계약

같은 앱 이미지·DB schema·seed로 로컬에서 S02~S04를 먼저 확인한다. D0A의 통과 증거는 `auth_decision_hash`, 관리자 세션/`upload_ticket_id`, 마커/`web_action_context_id`이며 로컬 성공은 AWS 골든 체인 횟수에 포함하지 않는다.

- 필수: Nginx request tap, ModSecurity CRS, Web/WAS, 로컬 MySQL 또는 RDS 호환 개발 DB, fixed action runner, request-envelope 생성·검증.
- 선택/비차단: HybridNB 모델 런타임. 인터페이스 contract test는 모델 없는 `evaluation_status=disabled_not_evaluated` envelope와 `result=not_evaluated` event로 만족한다.
- 비교: app image, CRS ruleset/config, fixture manifest, DB schema/seed hash. HybridNB model/preprocessing hash는 D5 이전에는 `not-applicable`이며 D5에서 별도 manifest로 동결한다.

### 2.3 D1-OBSERVABILITY: 공격 전 관측 게이트

정상 `BEN-*` 요청으로 UTC, `run_id`, 요청 ID, 보존 위치가 다음 모든 원시 로그에 남는 것을 증명한다. 한 항목이라도 누락되면 공격 구현보다 수집 경로를 먼저 수정한다.

<table fit-page-width="true" header-row="true">
	<tr>
		<td>수집 계층</td>
		<td>S01~S10 연결</td>
		<td>필수 상관 키</td>
		<td>단독 한계</td>
	</tr>
	<tr><td>ALB access</td><td>S01~S04, S10</td><td>source alias, request ID, path</td><td>본문/앱 권한 불가</td></tr>
	<tr><td>Nginx/ModSecurity</td><td>S01~S04</td><td>envelope hash, WAF transaction ID</td><td>SQLi 성공 불가</td></tr>
	<tr><td>D0 envelope/event contract</td><td>S02</td><td>request ID, schema version, body hash, `not_evaluated`</td><td>D5 전 모델 판정 없음</td></tr>
	<tr><td>Web/WAS</td><td>S02~S04, S08~S10</td><td>run_id, session hash, ticket ID</td><td>DB 실행 단독 불가</td></tr>
	<tr><td>auditd 또는 동등</td><td>S04~S05</td><td>process, UID, marker hash</td><td>cloud API 결과 불가</td></tr>
	<tr><td>Flow Logs</td><td>S01, S08~S09</td><td>ENI alias, 5-tuple, bytes</td><td>요청/SQL 내용 불가</td></tr>
	<tr><td>CloudTrail</td><td>S06~S07</td><td>role alias, source IP alias, event ID</td><td>앱 세션 불가</td></tr>
	<tr><td>S3 read data event</td><td>S07</td><td>object key/version, access-key fingerprint</td><td>객체 의미 불가</td></tr>
	<tr><td>RDS general/audit</td><td>S02, S09</td><td>DB user, query ID, UTC</td><td>HTTPS 전달 불가</td></tr>
</table>

CloudTrail management event만으로 S3 `GetObject`를 판정하지 않는다. 카나리 object/prefix의 S3 read data event를 별도 활성화한다. Flow Log byte 증가나 GuardDuty finding은 보조 증적이며, 단계 판정은 CloudTrail·앱·RDS 원시 로그를 결합한다.

## 3. 동결 토폴로지, 서브넷, 라우팅

```
Approved test CIDR
  -> Public ALB: HTTPS only
  -> private Web: Nginx / CRS / request tap / app / fixed action runner
  -> private WAS: business API + BASE lab admin API
  -> private RDS: MySQL synthetic data

Web/WAS -> interface VPC endpoints (SSM, ssmmessages, Logs; ECR only if approved)
Route tables -> S3 gateway endpoint
ALB, application, host, network, cloud, DB -> CloudWatch + private evidence S3
```

<table fit-page-width="true" header-row="true">
	<tr><td>영역</td><td>CIDR</td><td>배치</td><td>라우팅 계약</td></tr>
	<tr><td>Edge-A / Edge-B</td><td>`10.20.0.0/24`, `10.20.1.0/24`</td><td>ALB ENI</td><td>Internet Gateway 경로 보유</td></tr>
	<tr><td>Web-A / Web-B</td><td>`10.20.10.0/24`, `10.20.11.0/24`</td><td>Web EC2 또는 컨테이너 host</td><td>공인 IP 및 기본 인터넷 경로 없음</td></tr>
	<tr><td>WAS-A / WAS-B</td><td>`10.20.20.0/24`, `10.20.21.0/24`</td><td>WAS EC2 또는 컨테이너 host</td><td>공인 IP 및 기본 인터넷 경로 없음</td></tr>
	<tr><td>Data-A / Data-B</td><td>`10.20.30.0/24`, `10.20.31.0/24`</td><td>RDS subnet group</td><td>Internet Gateway/NAT 경로 없음</td></tr>
	<tr><td>Endpoint-A / Endpoint-B</td><td>Web 또는 전용 endpoint subnet</td><td>interface endpoints</td><td>PrivateLink, S3 gateway endpoint</td></tr>
</table>

ALB와 RDS subnet group은 두 AZ의 subnet을 사용한다. 비용상 Web/WAS 실행 노드는 최초 각 한 대일 수 있으나 이는 고가용성 검증이 아니다. NAT는 기본 설계에서 제외하며, 필요한 image는 사전 bake하거나 승인된 endpoint를 통해 취득한다.

### 3.1 보안 그룹 계약

<table fit-page-width="true" header-row="true">
	<tr><td>출발지</td><td>목적지</td><td>포트/프로토콜</td><td>용도</td></tr>
	<tr><td>승인 시험 CIDR</td><td>`sg-alb`</td><td>TCP 443</td><td>S01~S04, S10</td></tr>
	<tr><td>`sg-alb`</td><td>`sg-web`</td><td>TCP 8080 또는 D0 앱 포트</td><td>Nginx/Web 전달</td></tr>
	<tr><td>`sg-web`</td><td>`sg-was`</td><td>TCP 8081</td><td>정상 인증/업무 API</td></tr>
	<tr><td>`sg-web`</td><td>`sg-was`</td><td>TCP 8090</td><td>BASE 전용 ARGUS 관리 API, S08</td></tr>
	<tr><td>`sg-was`</td><td>`sg-rds`</td><td>TCP 3306</td><td>인증·업무 DB 연결</td></tr>
	<tr><td>`sg-web`, `sg-was`</td><td>`sg-vpce`</td><td>TCP 443</td><td>SSM, Logs, registry API</td></tr>
	<tr><td>Web route table</td><td>S3 gateway endpoint</td><td>HTTPS</td><td>카나리 `GetObject`, 관리 agent</td></tr>
</table>

- SSH/RDP 인바운드는 만들지 않는다. 운영 plane은 SSM만 사용한다.
- ALB는 WAS 관리 경로나 RDS를 proxy하지 않는다.
- 시험 단말은 WAS/RDS에 직접 연결할 수 없다.
- Web, WAS, RDS는 public IP와 `0.0.0.0/0` egress를 위한 NAT 경로를 갖지 않는다.

## 4. Terraform 구성, 소유권, 인터페이스

### 4.1 권장 file/module tree

```text
terraform/
  versions.tf
  providers.tf
  backend.tf
  variables.tf
  locals.tf
  outputs.tf
  main.tf
  environments/base.tfvars
  modules/
    network/          # VPC, subnets, routes, endpoints, security groups
    edge/             # ALB, listener, target group, TLS, access logging
    web/              # private compute, profile, Nginx/CRS/tap/runner config
    was/              # private compute and business/lab-admin API config
    data/             # RDS subnet/parameter group, schema bootstrap, synthetic seed
    canary/           # private bucket/object version, exact GetObject policy, data events
    observability/    # log groups, CloudTrail, Flow Logs, evidence bucket, retention
    safety/           # Budget, alarm, kill-switch inputs, resource manifest
  templates/
  manifests/
```

<table fit-page-width="true" header-row="true">
	<tr><td>모듈</td><td>소유/책임</td><td>입력 인터페이스</td><td>출력 인터페이스</td></tr>
	<tr><td>`network`</td><td>인프라</td><td>CIDRs, AZ IDs, approved CIDR, endpoint services</td><td>VPC/subnet/route/SG/VPCE IDs</td></tr>
	<tr><td>`edge`</td><td>인프라</td><td>edge subnets, `sg_alb`, TLS ARN, access-log bucket</td><td>ALB DNS/ARN, target group ARN</td></tr>
	<tr><td>`web`</td><td>Web+인프라</td><td>private Web subnets, `sg_web`, target group, artifact hashes, envelope interface version</td><td>instance/profile IDs, log group, Web target IDs</td></tr>
	<tr><td>`was`</td><td>WAS+인프라</td><td>private WAS subnets, `sg_was`, Web SG ID, schema endpoint</td><td>instance/profile IDs, app log group</td></tr>
	<tr><td>`data`</td><td>data+인프라</td><td>Data subnets, `sg_rds`, DB names/users, seed manifest hash</td><td>RDS endpoint, parameter group ID, seed result ID</td></tr>
	<tr><td>`canary`</td><td>cloud identity</td><td>Web role ID, object version/hash, event trail selector</td><td>bucket/object version, scoped policy ARN</td></tr>
	<tr><td>`observability`</td><td>detection+infrastructure</td><td>resource IDs, retention, evidence prefix, data-event selector</td><td>log/bucket/trail/flow-log IDs</td></tr>
	<tr><td>`safety`</td><td>infrastructure reviewer</td><td>budget ceiling, contacts, resource inventory inputs</td><td>alarm ARNs, manifest location</td></tr>
</table>

각 root 구성은 환경별 backend key를 명시한다. BASE와 HARDENED는 backend key, state, resource name prefix를 분리하고, 통제 실험을 위해 BASE 리소스를 제자리에서 수정하지 않는다.

### 4.2 변수, 출력, 이름/태그/state 규칙

필수 variables는 `aws_region`, `availability_zone_ids`, `vpc_cidr`, `subnet_cidrs`, `allowed_test_cidrs`, `environment`, `project`, `name_prefix`, `app_port`, `was_service_port`, `was_admin_port`, `db_port`, `artifact_manifest_sha256`, `fixture_manifest_sha256`, `db_seed_sha256`, `evidence_retention_days`, `budget_limit`, `enable_lab_mode`, `enable_s3_data_events`다. 비밀번호, access key, session token은 variable/`tfvars`/state에 넣지 않는다. DB secret은 승인된 secret reference만 전달하고 root output을 `sensitive`로 지정한다.

필수 outputs는 `alb_dns_name`, `alb_arn`, `vpc_id`, subnet/SG IDs, private instance IDs, `rds_endpoint`(sensitive where appropriate), canary bucket/object version, log group/trail/flow-log IDs, evidence bucket/prefix, Budget alarm ARN, `resource_manifest_uri`, `terraform_workspace_or_backend_key`다.

이름은 `<project>-<environment>-<component>-<purpose>` 형태를 사용한다. 모든 tag에는 `Project`, `Environment`, `ManagedBy=IaC`, `Component`, `Owner`, `Runbook`을 포함한다. 실행 manifest에는 IaC commit, plan SHA-256, app image, CRS config/ruleset, fixture, DB seed hash를 기록한다. HybridNB model/preprocessing hash는 D5 전 `deferred`이며 D5 산출물에서만 추가한다.

### 4.3 HybridNB request-envelope/event interface v1

Core는 versioned JSON Schema를 배포하고, 현재 checkout의 [`schemas/hybridnb-request-envelope-v1.json`](../../schemas/hybridnb-request-envelope-v1.json) 및 [`schemas/event-v1.json`](../../schemas/event-v1.json)와 contract test를 공유한다. 모델 endpoint는 이 단계에서 만들지 않는다.

```json
{
  "schema_version": "argus.hybridnb-envelope/v1",
  "request_id": "<internal-request-id>",
  "run_id": "ARGUS-<UTCDATE>-BASE-R<NN>",
  "source": "original_request",
  "method": "<approved-method>",
  "path": "<approved-path>",
  "body_sha256": "<64-lowercase-hex>",
  "evaluation_status": "disabled_not_evaluated"
}
```

D0A local evidence event는 `schema_version=argus.event/v1`과 `evidence_id`, `event_time_utc`, `run_id`, `stage_id` (`S02`/`S03`/`S04`), `event_type`, `request_id`, `result`를 필수로 한다. `evidence_id`와 `run_id`는 각각 `ARGUS-<UTCDATE>-LOCAL-R<NN>-S0[234]-E<NN>` 및 `ARGUS-<UTCDATE>-LOCAL-R<NN>` 형식이다. 공통 evidence 필드인 `source_ref`, `target_ref`, `action`, `fixture_or_resource_id`, `content_sha256`, `collector`, `reviewer`, `redaction_status`, `secret_material_present=false`도 필수다. `fixture_id`, `original_request_envelope`, `response_sha256`, `correlation`은 적용되는 event에 함께 기록한다. 모델을 평가하지 않는 D5 이전 event의 result는 `not_evaluated`를 사용하며, score/label/model hash를 만들어내지 않는다. D5에서만 model artifact/preprocessing hash, feature version, score/label/threshold를 별도 D5 event extension으로 동결한다.

## 5. 배포 순서와 작업 단위

1. **Preflight / D0:** AWS identity, region, backend bucket/key, provider version/lock, approved CIDR, artifact/seed manifest, cost stop threshold를 대조한다.
2. **D0A local contract:** AWS apply 전에 같은 app image, seed, CRS config로 S02~S04와 envelope/event v1 contract를 로컬로 검증한다. 모델은 `disabled_not_evaluated`/`not_evaluated`로 비차단 처리한다. D0A 미통과 시 BASE IaC apply를 진행하지 않는다.
3. **BASE network:** D0A 통과 후 VPC, subnet, route, IGW(Edge 전용), SG, S3 gateway/interface endpoints를 적용한다. NAT/public compute/db가 plan에 없는지 검토한다.
4. **Observability and safety:** evidence bucket, log group, ALB access logging, CloudTrail management + scoped S3 data event, Flow Logs, RDS logging parameters, Budget/alarm, resource manifest를 먼저 적용한다.
5. **Data and canary:** RDS subnet/parameter group/DB와 합성 seed, private canary object version, exact `GetObject` IAM만 배포한다. `ListBucket`, `PutObject`, `DeleteObject`는 허용하지 않는다.
6. **Compute and edge:** private Web/WAS, SSM instance profile, Nginx/CRS/tap, action runner allow-list, ALB target/listener를 배포한다.
7. **D1 observability:** 정상 fixture로 모든 수집 계층과 correlation key를 확인한다.
8. **D2 safety:** kill switch를 하나씩 작동·복구하고 독립 수집 경로가 계속 남는지 확인한다.
9. **D3/D4 stage then full chain:** 단계 계약과 고정 success token을 확인한 뒤 BASE 전체 체인 3회를 수행한다. 각 단계의 토큰이 없으면 다음 단계로 진행하지 않는다.
10. **D5 only:** 모델/전처리/임계값을 동결하고 동일 request envelope에 대해 WAF/HybridNB four-quadrant 및 policy evaluation을 수행한다.

## 6. Fixture, seed, run_id, evidence 연결

<table fit-page-width="true" header-row="true">
	<tr><td>항목</td><td>계약</td></tr>
	<tr><td>`run_id`</td><td>`ARGUS-<UTCDATE>-<ENV>-R<NN>`; 실행마다 새 값. 사용자 header를 무검증 신뢰하지 않고 서명된 manifest를 Nginx가 내부 요청 ID와 연결</td></tr>
	<tr><td>fixture</td><td>공격 `ATK-<FAMILY>-<NNN>`, 정상 `BEN-<FAMILY>-<NNN>`; 원문은 비공개, hash와 group ID만 공개본에 기록</td></tr>
	<tr><td>seed</td><td>`ARGUS-Q01`은 고정된 합성 view만 읽음. seed manifest SHA-256과 row/byte guard를 D0A와 AWS에서 확인</td></tr>
	<tr><td>evidence ID</td><td>`<run_id>-<stage_id>-E<NN>`; D0A local은 `ARGUS-<UTCDATE>-LOCAL-R<NN>-S0[234]-E<NN>`</td></tr>
	<tr><td>handoff</td><td>단계 토큰 없이는 다음 단계 금지. one-time, TTL, consume/expire event가 필수</td></tr>
</table>

S02~S10의 전달물은 설계의 `auth_decision_hash` -> `upload_ticket_id` -> `web_action_context_id` -> `credential_handoff_id` -> S3 canary -> `was_bundle_handoff_id` -> `db_read_ticket_id` -> `db_result_manifest_id` -> `delivery_sha256` 순서를 따른다. action runner는 `MARKER`, `IMDS_IDENTITY`, `WAS_AUTH`만 allow-list로 실행하며 자유 명령, URL, 파일 경로를 받지 않는다.

공통 evidence record에는 `evidence_id`, `run_id`, `stage_id`, `event_time_utc`, `source_ref`, `target_ref`, `action`, `result`, `fixture_or_resource_id`, `content_sha256`, `collector`, `reviewer`, `redaction_status`, `secret_material_present=false`를 기록한다. 공개 산출물에는 secret, 세션, 계정 번호, 내부 주소, access key 원문을 넣지 않는다.

## 7. 속도, 데이터, 비용, 안전 중지

- 온라인 재생은 concurrency `1`, 최대 `1 rps`, 요청 간 최소 1초다. S02의 D5 탐지 정책 재생 총량은 960건 상한이며 D5 전 Core는 이 재생을 수행하지 않는다.
- S09와 S10은 결과를 모두 반환하기 전에 **최대 10행 및 32 KiB**를 검사하고, 초과 시 실패 event를 남긴 뒤 중지한다.
- RDS, ALB, CloudWatch Logs, GuardDuty, S3 data event 비용은 태그와 Budget alarm으로 분리 추적한다. RDS general/audit log는 실습 window와 retention에 맞춰 제한한다.
- 허용 목록 밖 source/target, 비합성 데이터, credential 원문, 10행/32 KiB 초과, 예상하지 않은 write/delete, 수집 중단, 비용 alarm, 서비스 오류율/지연의 RoE 초과가 하나라도 발생하면 즉시 중지한다.

### Kill switch 순서

1. ALB SG에서 승인 CIDR 제거
2. Nginx 또는 WAF에 임시 block-all 적용
3. Web instance에서 시험 role 분리
4. canary bucket policy로 exact `GetObject` 차단
5. `sg-was`의 TCP 8090 rule 제거
6. `ARGUS_LAB_MODE=enabled` 비활성화 또는 취약 app 중지

kill switch와 central evidence path는 취약 application session 또는 EC2 test role에 의존하지 않아야 한다. 시험 시간 밖에는 ALB allowlist를 제거하거나 stack을 중지한다.

## 8. PowerShell 검증 런북

### 8.1 AWS identity, region, state 사전 확인 (read-only)

```powershell
$ErrorActionPreference = 'Stop'
$env:AWS_PROFILE = 'PowerCodex'
aws sts get-caller-identity
aws configure get region
aws ec2 describe-availability-zones --region <final-region> --query 'AvailabilityZones[].{Name:ZoneName,Id:ZoneId}' --output table
```

원격 state를 확인할 때는 이미 초기화된 D0의 BASE backend/key만 대상으로 한다. 다른 환경 state를 읽거나 변경하지 않는다.

```powershell
$ErrorActionPreference = 'Stop'
$env:AWS_PROFILE = 'PowerCodex'
terraform state list
```

### 8.2 Local Terraform initialization (writes local metadata)

다음은 checkout의 `.terraform` metadata와 provider lock file을 만들거나 갱신할 수 있으므로 read-only 점검이 아니다. 변경 전후 lock file diff를 검토한다.

```powershell
$ErrorActionPreference = 'Stop'
terraform version
terraform init -backend=false
terraform validate
```

### 8.3 Plan-only proof

```powershell
$ErrorActionPreference = 'Stop'
terraform fmt -check -recursive
terraform init
terraform validate
terraform plan -var-file='environments/base.tfvars' -out='base.tfplan'
terraform show -json 'base.tfplan' | Out-File -Encoding ascii 'base.tfplan.json'
```

위 명령은 형식, provider/구성, 예상 변경만 검증한다. ALB health, log delivery, private routing, S3 deny, RDS logging, 실제 cleanup은 증명하지 않는다.

### 8.4 승인된 apply 후 런타임 확인

`apply`는 비용이 발생하는 별도 승인 작업이다. 다음은 apply가 승인되어 성공한 뒤에만 수행한다.

```powershell
$ErrorActionPreference = 'Stop'
$env:AWS_PROFILE = 'PowerCodex'
terraform apply 'base.tfplan'
aws elbv2 describe-target-health --target-group-arn <target-group-arn>
aws ec2 describe-instances --filters 'Name=tag:Project,Values=ARGUS' 'Name=tag:Environment,Values=BASE' --query 'Reservations[].Instances[].{Id:InstanceId,PublicIp:PublicIpAddress,Subnet:SubnetId,State:State.Name}' --output table
aws rds describe-db-instances --db-instance-identifier <db-identifier> --query 'DBInstances[0].PubliclyAccessible'
aws logs describe-log-groups --log-group-name-prefix '/argus/base/'
aws cloudtrail get-event-selectors --trail-name <trail-name>
```

`PublicIp`가 Web/WAS에 비어 있고 RDS `PubliclyAccessible`가 `false`인지, target health가 정상인지, S3 data event selector가 canary object/prefix로 제한되어 있는지 확인한다. 그 뒤 D1의 정상 `BEN-*` 요청 한 건으로 각 raw log와 correlation key를 수집한다. 이 명령 집합만으로 D1 또는 전체 체인 성공을 주장하지 않는다.

### 8.5 Destroy 및 잔여 자원 확인

destroy는 승인된 종료 절차에서만 실행한다. 실행 전에 state와 plan의 대상이 BASE backend/key임을 확인하고, evidence 보존·redaction 의무를 확인한다.

```powershell
$ErrorActionPreference = 'Stop'
$env:AWS_PROFILE = 'PowerCodex'
terraform plan -destroy -var-file='environments/base.tfvars' -out='base-destroy.tfplan'
terraform show 'base-destroy.tfplan'
terraform apply 'base-destroy.tfplan'
terraform state list
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=ARGUS Key=Environment,Values=BASE --output table
aws ec2 describe-network-interfaces --filters 'Name=tag:Project,Values=ARGUS' 'Name=tag:Environment,Values=BASE' --output table
aws logs describe-log-groups --log-group-name-prefix '/argus/base/'
```

잔여 log/evidence bucket은 의도한 보존 정책인지, 또는 비용 잔여 자원인지 구분해 manifest에 기록한다. 두 시점의 create/destroy cycle을 독립적으로 확인하기 전에는 재현성 완료로 판정하지 않는다.

## 9. D1 종료 기준

- [ ] ALB만 외부 도달 가능하며 승인 CIDR의 TCP 443만 허용된다.
- [ ] Web/WAS/RDS는 public IP가 없고 Web->WAS 업무/관리 포트와 WAS->RDS 3306 외 경로가 없다.
- [ ] NAT가 없고 SSM, `ssmmessages`, Logs, S3 gateway endpoint가 작동한다. ECR endpoint는 실제 사용 시에만 추가한다.
- [ ] RDS/S3에는 합성 데이터만 있으며 S3 role은 exact canary `GetObject`만 허용한다.
- [ ] D0A에서 모델 없이 S02~S04와 envelope/event v1 contract가 통과한다.
- [ ] 정상 요청 한 건이 ALB, Nginx/CRS, Web/WAS, auditd, Flow Logs, CloudTrail, scoped S3 data event, RDS, D0 envelope/event contract에 UTC/correlation key로 연결된다.
- [ ] 각 raw log의 보존 위치, collector, redaction 상태와 단독 판정 한계를 evidence manifest에 기록했다.
- [ ] `terraform fmt`, init, validate, plan proof와 apply 후 runtime evidence를 구분해 보관했다.

### D1 이후 BASE/G1 acceptance (D1 종료 기준 아님)

- [ ] D2에서 kill switch 여섯 개를 작동·복구하고 독립 증적 수집이 유지됨을 확인했다.
- [ ] D3/D4에서 단계 토큰과 원시 증적을 갖춘 BASE 전체 체인 3회를 재현했다.
- [ ] 서로 다른 시점의 IaC create/destroy cycle 두 번과 비용/잔여 자원 manifest를 확인했다.

## 10. 구현 체크리스트

- [ ] D0 변수와 TODO 값을 승인·동결하고 BASE backend/key를 분리했다.
- [ ] network/edge/web/was/data/canary/observability/safety 모듈의 입력/출력 계약을 구현했다.
- [ ] public ALB only, private Web/WAS/RDS, no NAT, endpoint-only management를 plan과 runtime에서 각각 확인했다.
- [ ] SG ingress/egress가 표의 명시된 경로에 한정됨을 코드 리뷰했다.
- [ ] app/seed/fixture/CRS hash와 plan hash를 run manifest에 연결했다.
- [ ] request-envelope v1과 event v1 contract test를 구현했다. 모델 추론은 호출하지 않았다.
- [ ] CloudTrail management 및 scoped S3 read data event, Flow Logs, RDS log, app/host logs를 수집했다.
- [ ] `run_id`, evidence ID, success token, one-time TTL/consume/expire 기록을 구현했다.
- [ ] 1 rps/concurrency 1 및 10행/32 KiB guard를 테스트했다.
- [ ] Budget/alarm, kill switch, ALB allowlist removal, resource manifest, destroy residual check를 검토했다.
- [ ] D5 작업을 별도 change set으로 유지했으며 WAF/HybridNB 4분면을 D1/D4 완료 조건에 섞지 않았다.

## 11. 명시적 보류 및 권위 원천의 공백

다음 값은 현재 원천이 고정하지 않아 TODO로 남긴다. 구현자가 임의 값으로 조용히 대체하지 말고 D0 동결표에 승인 근거와 함께 기록한다.

1. 최종 AWS account ID, region, AZ IDs, approved test CIDR.
2. AMI/container image hash, instance/RDS class, TLS certificate ARN, 최종 ALB->Web 앱 포트.
3. Terraform backend 유형·bucket/key·lock configuration, evidence/log retention 기간.
4. budget/cost stop threshold, 허용 실습 window, 담당자/교차검토자.
5. SSM/`ssmmessages`/Logs 외 ECR endpoint 필요 여부.
6. HybridNB model artifact, preprocessing, runtime, threshold, feature list 및 D5 four-quadrant 결과. 이는 의도적으로 `D5-DUAL-DETECTION` 보류다.

## Sources

### Primary Notion sources

- <mention-page url="https://app.notion.com/p/3adf118fd3928036bc10f1dfb5d6d949"/>: 교체 대상 AWS 3-Tier BASE 환경 구축
- <mention-page url="https://app.notion.com/p/3b4f118fd3928192a7c4fe6ff42458d5"/>: BASE topology, subnet, security group, IaC, observability, safety contract
- <mention-page url="https://app.notion.com/p/3adf118fd39280d08462c7aca850a1af"/>: S01~S10, run/evidence, handoff, independent detection contract
- <mention-page url="https://app.notion.com/p/3adf118fd3928001993acdf23bf0c56c"/>: project objective, gates, completion boundary

### Derived implementation invariants

- `10.20.0.0/16`; public entrypoint는 allowlisted HTTPS ALB 하나이며 Web/WAS/RDS는 private이다.
- NAT는 없고 SSM, `ssmmessages`, Logs interface endpoint와 S3 gateway endpoint가 필요하다.
- 보안 그룹은 승인 CIDR->ALB 443, ALB->Web 8080/D0 port, Web->WAS 8081/8090, WAS->RDS 3306만 허용한다.
- 실습은 합성 데이터, fixed fixture/action, one-time handoff, 1 rps/concurrency 1, 10행/32 KiB에 한정된다.
- 환경 배포 후 공격 전에 D1 원시 로그 수집과 D2 kill switch가 필요하며, plan proof와 runtime proof는 분리한다.
- D5 이전 HybridNB는 request-envelope/event interface만 보장하고, 모델 및 WAF/HybridNB comparison은 D5에서 수행한다.
