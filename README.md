# listup_aws_resources

AWS 리소스를 나열하고 정리하는 스크립트입니다. 특정 AWS 계정에서 자주 사용하는 리소스의 상태를 조회하여 엑셀 및 JSON 형태로 데이터를 내보냅니다.

추가하고 싶은 AWS 리소스가 있다면, `resources` 폴더에 새로운 리소스를 정의할 수 있습니다. (PR 환영합니다!)

## 🚀 새로운 기능

- **리소스 선택 기능**: 원하는 AWS 리소스만 선택적으로 조회 가능
- **다중 리전 지원**: 여러 리전을 동시에 조회
- **Security Groups 전용 분석**: `--resources security_groups`로 상세한 보안 분석 제공
- **향상된 사용자 경험**: 진행 상황 표시 및 결과 요약

## 기능

- **27개 AWS 리소스** 지원 (EKS, EC2, S3, RDS, DynamoDB, Route53, EIP, Internet Gateway, Security Group 등)
- 조회된 결과는 **Excel, CSV, JSON** 형식으로 저장
- **Security Group** 리소스에서 0.0.0.0/0 또는 ::/0 AnyOpen된 Inbound Rule을 가진 항목은 '⚠️ YES'로 표시
- **Security Group 사용 리소스 추적**: 연결된 ENI, 로드 밸런서, RDS, 서버리스 리소스를 함께 제공
- **IPv6 범위, Prefix List ID, 보안 그룹 참조** 등 모든 유형의 보안 그룹 규칙을 완전히 지원
- **SES Identity** 리소스에서 이메일 자격 증명의 확인 상태, DKIM 상태, 알림 설정 등을 확인
- 강력한 **에러 처리**와 **타입 힌트**로 안정성과 가독성을 보장

## 지원되는 AWS 리소스 (27개)

### 컴퓨팅 & 컨테이너
- **EC2** - 가상 서버 인스턴스
- **EKS** - Kubernetes 클러스터
- **ECR** - 컨테이너 레지스트리
- **Auto Scaling Groups** - 오토스케일링 그룹
- **AMIs** - Amazon Machine Images

### 네트워킹
- **VPC** - 가상 프라이빗 클라우드
- **Subnets** - 서브넷
- **Security Groups** - 보안 그룹
- **Security Group Rules** - 보안 그룹 규칙
- **EIP** - Elastic IP 주소
- **Internet Gateway** - 인터넷 게이트웨이
- **NAT Gateway** - NAT 게이트웨이
- **VPC Endpoints** - VPC 엔드포인트
- **ELB** - 로드 밸런서 (Classic, ALB, NLB)

### 스토리지
- **S3** - 객체 스토리지 (글로벌)
- **EBS Volumes** - 블록 스토리지
- **EBS Snapshots** - EBS 스냅샷

### 데이터베이스 & 캐시
- **RDS** - 관계형 데이터베이스
- **DynamoDB** - NoSQL 데이터베이스
- **ElastiCache** - 인메모리 캐시

### 기타 서비스
- **Route53** - DNS 서비스 (글로벌)
- **Global Accelerator** - 글로벌 가속기 (글로벌)
- **Kinesis Streams** - 실시간 데이터 스트리밍
- **Kinesis Firehose** - 데이터 전송 서비스
- **Glue Jobs** - ETL 작업
- **Secrets Manager** - 비밀 관리
- **SES Identity** - 이메일 서비스

## 프로젝트 구조

```shell
listup_aws_resources/
├── data/
│   └── YYYYMMDD_HHmmss/
│       ├── aws_resources.xlsx
│       ├── aws_resources.csv
│       └── aws_resources.json
├── resources/
│   ├── amis.py
│   ├── auto_scaling_groups.py
│   ├── dynamodb.py
│   ├── ebs.py
│   ├── ebs_snapshot.py
│   ├── ec2.py
│   ├── ecr.py
│   ├── eip.py
│   ├── eks.py
│   ├── elasticache.py
│   ├── elb.py
│   ├── glue_job.py
│   ├── global_accelerator.py
│   ├── internet_gateway.py
│   ├── kinesis_firehose.py
│   ├── kinesis_streams.py
│   ├── nat_gateway.py
│   ├── rds.py
│   ├── route53_hostedzone.py
│   ├── s3_buckets.py
│   ├── secrets_manager.py
│   ├── security_groups.py
│   ├── ses_identity.py
│   ├── subnets.py
│   ├── vpc.py
│   └── vpc_endpoint.py
├── tests/
│   ├── test_datetime_format.py
│   ├── test_ec2.py
│   ├── test_listup_aws_resources.py
│   ├── test_s3_buckets.py
│   ├── test_security_groups.py
│   └── test_ses_identity.py
├── utils/
│   ├── datetime_format.py
│   └── name_tag.py
├── listup_aws_resources.py
├── pyproject.toml
├── uv.lock
└── README.md
```

## 설치 및 실행 방법

1. 저장소를 클론합니다.

```bash
git clone https://github.com/KKamJi98/listup_aws_resources.git
cd listup_aws_resources
```

2. `uv` 가상 환경을 생성하고 활성화합니다.

```bash
uv venv
source .venv/bin/activate
```

3. 의존성을 설치합니다.

```bash
uv sync
```

4. AWS 자격증명(credential)을 환경에 설정합니다.

```bash
export AWS_ACCESS_KEY_ID=<your_access_key>
export AWS_SECRET_ACCESS_KEY=<your_secret_key>
export AWS_DEFAULT_REGION=<your_region>
```

## 사용 방법

### 1. 전체 AWS 리소스 조회

#### 기본 사용법
```bash
# 모든 리소스, 기본 리전 (ap-northeast-2)
python listup_aws_resources.py

# 특정 리전들에서 모든 리소스 조회
python listup_aws_resources.py --region ap-northeast-2 us-east-1 ap-southeast-1
```

#### 특정 리소스만 조회
```bash
# 특정 리소스들만 조회
python listup_aws_resources.py --resources ec2 rds s3

# 특정 리전에서 특정 리소스들만 조회
python listup_aws_resources.py --region ap-southeast-1 --resources ec2 vpc security_groups

# 사용 가능한 리소스 목록 확인
python listup_aws_resources.py --list-resources
```

#### 도움말
```bash
python listup_aws_resources.py --help
```

### 2. Security Groups 전용 조회

```bash
# Security Groups만 조회 (상세 보안 분석 포함)
python listup_aws_resources.py --resources security_groups

# 특정 리전의 Security Groups 조회
python listup_aws_resources.py --resources security_groups --region ap-southeast-1

# 여러 리전의 Security Groups 조회
python listup_aws_resources.py --resources security_groups --region ap-northeast-2 us-east-1

# 도움말
python listup_aws_resources.py --help
```

## 개발 및 테스트

### 테스트 실행

```bash
# 모든 테스트 실행
uv run pytest -v

# 특정 모듈 테스트
uv run pytest tests/test_security_groups.py -v
```

### 코드 품질 검사

```bash
# 코드 포맷팅 검사
uv run black --check .

# Import 정렬 검사
uv run isort --check-only .

# 코드 포맷팅 적용
uv run black .
uv run isort .
```

### 모든 검사 실행

```bash
# 테스트, 포맷팅, Import 정렬을 모두 확인
uv run pytest -v && uv run isort --check-only . && uv run black --check .
```

### 실행 예시

```bash
python listup_aws_resources.py

🚀 AWS 리소스 조회 스크립트 시작
==================================================
🌍 조회 리전: ap-northeast-2
📋 모든 리소스를 조회합니다.

=== Collecting resources in region: ap-northeast-2 ===
  🖥️  EC2 조회 중...
  🌐 VPC 조회 중...
  ... (중략)

🪣 S3 Buckets (글로벌) 조회 중...
🚀 Global Accelerator (글로벌) 조회 중...
🌐 Route53 HostedZones (글로벌) 조회 중...

📊 Excel 파일 생성 완료: ./data/20251002_112348/aws_resources.xlsx
📄 CSV 파일 생성 완료: ./data/20251002_112348/aws_resources.csv
📄 JSON 파일 생성 완료: ./data/20251002_112348/aws_resources.json

✅ AWS 리소스 조회 완료!
🌍 조회된 리전: ap-northeast-2
📋 모든 리소스가 조회되었습니다.
  📍 ap-northeast-2: 47개 리소스
  🌐 S3: 2개 리소스
  🌐 Route53: 1개 리소스
📊 총 조회된 리소스: 50개
```

## 결과물

### 전체 리소스 조회 결과
- **출력 디렉터리**: `./data/YYYYMMDD_HHmmss/` (요청마다 새 폴더 생성)
- **Excel 파일**: `aws_resources.xlsx` - 시트별로 정리된 가공 데이터
- **CSV 파일**: `aws_resources.csv` - 리전, 리소스 유형, 주요 속성을 한 시트로 평탄화
- **JSON 파일**: `aws_resources.json` - 원본(raw) 및 필터링(filtered) 데이터를 모두 포함하고 실행 메타데이터를 함께 저장

### Security Groups 전용 조회 결과
Security Groups만 조회할 때도 동일한 파일 형식으로 저장되며, 추가로 상세한 보안 분석 결과가 콘솔에 출력됩니다:
- 리전별 Security Groups 수 및 AnyOpen 규칙 통계
- 전체 보안 점수 계산
- 보안 주의가 필요한 Security Groups 목록
- 보안 권장사항 제공

## 주요 개선사항

### 리소스 선택 기능
- 원하는 AWS 리소스만 선택적으로 조회 가능
- 시간 절약 및 효율적인 리소스 관리
- 27개 리소스 중 필요한 것만 선택

### Security Groups 모듈
- IPv4 (0.0.0.0/0) 및 IPv6 (::/0) AnyOpen 규칙 감지
- IPv6 범위, Prefix List ID, 보안 그룹 참조 완전 지원
- ENI, 로드 밸런서, RDS, 서버리스 등 SG를 사용하는 리소스를 추적하고 `AttachedResources`, `AttachedResourceCount` 컬럼으로 제공
- 향상된 에러 처리 및 타입 힌트
- 포괄적인 테스트 커버리지

### 사용자 경험 개선
- 진행 상황 표시 (이모지 포함)
- 조회 결과 요약 정보
- 리전별 리소스 수 통계
- 명확한 도움말 및 사용 예시

### 공통 개선사항
- 모든 모듈에 타입 힌트 추가
- 강화된 에러 처리 (ClientError 및 일반 예외)
- 표준화된 datetime 포맷팅 유틸리티 사용
- 포괄적인 단위 테스트 작성

## 사용 예시

### 네트워킹 리소스만 조회
```bash
python listup_aws_resources.py --resources vpc subnets security_groups internet_gateway nat_gateway
```

### 컴퓨팅 리소스만 조회
```bash
python listup_aws_resources.py --resources ec2 eks ecr auto_scaling_groups amis
```

### 글로벌 리소스만 조회
```bash
python listup_aws_resources.py --resources s3 route53 global_accelerator
```

### 특정 리전의 보안 관련 리소스 조회
```bash
python listup_aws_resources.py --region ap-northeast-2 --resources security_groups secrets_manager
```

### Security Groups 전용 보안 분석
```bash
python listup_aws_resources.py --resources security_groups --region ap-southeast-1
```

## TODO

- [x] 공통되게 사용되는 DateTime Format을 (%Y-%m-%d)로 수정하는 코드를 함수화
- [x] Security Groups에서 IPv6 및 Prefix List 지원 추가
- [x] 모든 모듈에 타입 힌트 및 에러 처리 개선
- [x] 포괄적인 테스트 커버리지 구현
- [x] 리소스 선택 기능 추가
- [x] Security Groups 전용 스크립트 추가
- [ ] Lambda Functions 리소스 추가
- [ ] CloudWatch Alarms 리소스 추가
- [ ] IAM Roles/Users 리소스 추가

## 기여

이슈를 생성하거나 PR을 보내 기여할 수 있습니다. 모든 PR은 다음 조건을 만족해야 합니다:

- `pytest`, `isort`, `black` 모든 검사 통과
- 새로운 기능에 대한 테스트 포함
- 타입 힌트 및 적절한 에러 처리 포함

## 라이선스

이 프로젝트는 MIT 라이선스를 따릅니다.

## 버전

현재 버전은 1.3.0입니다.

## 작성자

- 이메일: rlaxowl5460@gmail.com
- GitHub: [KKamJi98](https://github.com/KKamJi98)
