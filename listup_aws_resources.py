import argparse
import json
import os
from datetime import date, datetime, timezone
from typing import Any

import boto3
import pandas as pd

from resources.amis import get_filtered_data as amis_filtered
from resources.amis import get_raw_data as amis_raw
from resources.auto_scaling_groups import (
    get_filtered_data as auto_scaling_groups_filtered,
)
from resources.auto_scaling_groups import get_raw_data as auto_scaling_groups_raw
from resources.dynamodb import get_filtered_data as dynamodb_filtered
from resources.dynamodb import get_raw_data as dynamodb_raw
from resources.ebs import get_filtered_data as ebs_filtered
from resources.ebs import get_raw_data as ebs_raw
from resources.ebs_snapshot import get_filtered_data as ebs_snapshot_filtered
from resources.ebs_snapshot import get_raw_data as ebs_snapshot_raw
from resources.ec2 import get_filtered_data as ec2_filtered
from resources.ec2 import get_raw_data as ec2_raw
from resources.ecr import get_filtered_data as ecr_filtered
from resources.ecr import get_raw_data as ecr_raw
from resources.eip import get_filtered_data as eip_filtered
from resources.eip import get_raw_data as eip_raw
from resources.eks import get_filtered_data as eks_filtered
from resources.eks import get_raw_data as eks_raw
from resources.elasticache import get_filtered_data as elasticache_filtered
from resources.elasticache import get_raw_data as elasticache_raw
from resources.elb import get_filtered_data as elb_filtered
from resources.elb import get_raw_data as elb_raw
from resources.global_accelerator import get_filtered_data as ga_filtered
from resources.global_accelerator import get_raw_data as ga_raw
from resources.glue_job import get_filtered_data as glue_job_filtered
from resources.glue_job import get_raw_data as glue_job_raw
from resources.internet_gateway import get_filtered_data as internet_gateway_filtered
from resources.internet_gateway import get_raw_data as internet_gateway_raw
from resources.kinesis_firehose import get_filtered_data as kinesis_firehose_filtered
from resources.kinesis_firehose import get_raw_data as kinesis_firehose_raw
from resources.kinesis_streams import get_filtered_data as kinesis_streams_filtered
from resources.kinesis_streams import get_raw_data as kinesis_streams_raw
from resources.nat_gateway import get_filtered_data as nat_gateway_filtered
from resources.nat_gateway import get_raw_data as nat_gateway_raw
from resources.rds import get_filtered_data as rds_filtered
from resources.rds import get_raw_data as rds_raw
from resources.route53_hostedzone import get_filtered_data as route53_filtered
from resources.route53_hostedzone import get_raw_data as route53_raw
from resources.s3_buckets import get_filtered_data as s3_filtered
from resources.s3_buckets import get_raw_data as s3_raw
from resources.secrets_manager import get_filtered_data as secrets_filtered
from resources.secrets_manager import get_raw_data as secrets_raw
from resources.security_group_rules import (
    get_filtered_data as security_group_rules_filtered,
)
from resources.security_group_rules import get_raw_data as security_group_rules_raw
from resources.security_groups import get_filtered_data as security_groups_filtered
from resources.security_groups import get_raw_data as security_groups_raw
from resources.ses_identity import get_filtered_data as ses_identity_filtered
from resources.ses_identity import get_raw_data as ses_identity_raw
from resources.subnets import get_filtered_data as subnets_filtered
from resources.subnets import get_raw_data as subnets_raw
from resources.vpc import get_filtered_data as vpc_filtered
from resources.vpc import get_raw_data as vpc_raw
from resources.vpc_endpoint import get_filtered_data as vpc_endpoint_filtered
from resources.vpc_endpoint import get_raw_data as vpc_endpoint_raw


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime | date):
            return obj.isoformat()
        return super().default(obj)


def _stringify_csv_value(value: Any) -> str:
    """CSV에 기록하기 위해 값을 문자열로 변환한다."""

    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _prepare_csv_record(
    region: str, resource_type: str, record: dict[str, Any]
) -> dict[str, Any]:
    """CSV 행 생성을 위한 레코드를 구성한다."""

    row: dict[str, Any] = {"Region": region, "ResourceType": resource_type}
    for key, value in record.items():
        column = key
        if key == "Region":
            column = "RecordRegion"
        elif key == "ResourceType":
            column = "RecordResourceType"

        if isinstance(value, list):
            row[column] = "; ".join(_stringify_csv_value(item) for item in value)
        elif isinstance(value, dict):
            row[column] = json.dumps(value, ensure_ascii=False)
        else:
            row[column] = _stringify_csv_value(value)
    return row


def _build_csv_rows(all_filtered_data: dict[str, Any]) -> list[dict[str, Any]]:
    """전체 필터링 데이터에서 CSV 행 목록을 생성한다."""

    rows: list[dict[str, Any]] = []
    for region, region_data in all_filtered_data.items():
        if isinstance(region_data, dict):
            for resource_type, records in region_data.items():
                for record in records:
                    rows.append(
                        _prepare_csv_record(
                            region=region, resource_type=resource_type, record=record
                        )
                    )
        elif isinstance(region_data, list):
            for record in region_data:
                rows.append(
                    _prepare_csv_record(
                        region="Global", resource_type=region, record=record
                    )
                )
    return rows


def print_security_groups_analysis(all_filtered_data: dict):
    """
    Security Groups 전용 조회 시 상세한 보안 분석을 출력합니다.

    Args:
        all_filtered_data: 필터링된 데이터 딕셔너리
    """
    print("\n🔍 Security Groups 보안 분석 결과:")
    print("=" * 50)

    total_security_groups = 0
    total_any_open = 0
    any_open_details = []

    # 각 리전별 Security Groups 분석
    for region, region_data in all_filtered_data.items():
        if region in ["S3", "GlobalAccelerator", "Route53"]:  # 글로벌 리소스 제외
            continue

        if "SecurityGroups" in region_data:
            sg_data = region_data["SecurityGroups"]
            region_total = len(sg_data)
            region_any_open = len(
                [sg for sg in sg_data if sg.get("AnyOpenInbound") == "⚠️ YES"]
            )

            total_security_groups += region_total
            total_any_open += region_any_open

            if region_total > 0:
                print(f"📍 {region}: {region_total}개 Security Groups", end="")
                if region_any_open > 0:
                    print(f" (⚠️ {region_any_open}개 AnyOpen)")
                    # AnyOpen Security Groups 상세 정보 수집
                    for sg in sg_data:
                        if sg.get("AnyOpenInbound") == "⚠️ YES":
                            any_open_details.append(
                                {
                                    "region": region,
                                    "id": sg.get("SecurityGroupId", ""),
                                    "name": sg.get("SecurityGroupName", ""),
                                    "vpc": sg.get("VpcId", ""),
                                }
                            )
                else:
                    print(" (✅ 모두 안전)")

    # 전체 요약
    print("\n📊 전체 요약:")
    print(f"  🛡️  총 Security Groups: {total_security_groups}개")
    print(f"  ⚠️  AnyOpen 인바운드 규칙: {total_any_open}개")

    if total_any_open > 0:
        security_percentage = (
            (total_security_groups - total_any_open) / total_security_groups
        ) * 100
        print(
            f"  📈 보안 점수: {security_percentage:.1f}% ({total_security_groups - total_any_open}/{total_security_groups})"
        )

        print("\n⚠️  보안 주의가 필요한 Security Groups:")
        for detail in any_open_details:
            print(f"    - {detail['id']} ({detail['name']}) in {detail['region']}")
            if detail["vpc"]:
                print(f"      VPC: {detail['vpc']}")

        print("\n💡 보안 권장사항:")
        print("  • 0.0.0.0/0 또는 ::/0 인바운드 규칙을 특정 IP 범위로 제한하세요")
        print("  • 필요한 포트만 열어두고 불필요한 포트는 차단하세요")
        print("  • 정기적으로 Security Groups 규칙을 검토하세요")
    else:
        print("  ✅ 모든 Security Groups가 안전합니다!")


def get_available_resources():
    """사용 가능한 AWS 리소스 목록을 반환합니다."""
    return {
        "ec2": "EC2 인스턴스",
        "vpc": "VPC (Virtual Private Cloud)",
        "rds": "RDS 데이터베이스",
        "eks": "EKS 클러스터",
        "subnets": "서브넷",
        "dynamodb": "DynamoDB 테이블",
        "elb": "ELB 로드밸런서",
        "elasticache": "ElastiCache",
        "ebs": "EBS 볼륨",
        "ebs_snapshot": "EBS 스냅샷",
        "amis": "AMI 이미지",
        "nat_gateway": "NAT 게이트웨이",
        "vpc_endpoint": "VPC 엔드포인트",
        "kinesis_streams": "Kinesis Data Streams",
        "glue_job": "Glue 작업",
        "kinesis_firehose": "Kinesis Data Firehose",
        "secrets_manager": "Secrets Manager",
        "eip": "Elastic IP",
        "internet_gateway": "인터넷 게이트웨이",
        "security_groups": "보안 그룹",
        "ecr": "ECR 레지스트리",
        "security_group_rules": "보안 그룹 규칙",
        "auto_scaling_groups": "Auto Scaling 그룹",
        "ses_identity": "SES Identity",
        "s3": "S3 버킷 (글로벌)",
        "global_accelerator": "Global Accelerator (글로벌)",
        "route53": "Route53 호스팅 영역 (글로벌)",
    }


def main():
    """
    명령줄 인자로 전달된 리전 목록과 리소스 목록에 대해 AWS 리소스를 수집하여 JSON 및 Excel 파일로 저장합니다.
    글로벌 리소스(S3, Global Accelerator, Route53)는 별도 처리하며,
    선택된 리소스만 조회할 수 있습니다.
    """
    available_resources = get_available_resources()

    parser = argparse.ArgumentParser(
        description="AWS 리소스 조회 스크립트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
사용 가능한 리소스:
{chr(10).join([f"  {key}: {desc}" for key, desc in available_resources.items()])}

사용 예시:
  python listup_aws_resources.py                                    # 모든 리소스, 기본 리전
  python listup_aws_resources.py --region ap-northeast-2 us-east-1  # 특정 리전들
  python listup_aws_resources.py --resources ec2 rds s3             # 특정 리소스들만
  python listup_aws_resources.py --region ap-northeast-2 --resources ec2 vpc security_groups  # 특정 리전, 특정 리소스들
  python listup_aws_resources.py --resources security_groups        # Security Groups 전용 (상세 보안 분석 포함)
  python listup_aws_resources.py --resources security_groups --region ap-southeast-1  # 특정 리전 Security Groups 분석
        """,
    )

    parser.add_argument(
        "--region",
        dest="regions",
        nargs="+",
        default=["ap-northeast-2"],
        help="조회할 AWS 리전명 (여러 개 가능). 기본값: ap-northeast-2",
    )

    parser.add_argument(
        "--resources",
        dest="selected_resources",
        nargs="+",
        choices=list(available_resources.keys()),
        help="조회할 AWS 리소스 (여러 개 가능). 지정하지 않으면 모든 리소스를 조회합니다.",
    )

    parser.add_argument(
        "--list-resources",
        action="store_true",
        help="사용 가능한 리소스 목록을 출력하고 종료",
    )

    # Check if running in a test environment
    import sys

    if "pytest" in sys.modules:
        args = parser.parse_args([])  # Pass empty list to avoid parsing test arguments
    else:
        args = parser.parse_args()

    # 리소스 목록 출력 후 종료
    if args.list_resources:
        print("🔍 사용 가능한 AWS 리소스:")
        print("=" * 50)
        for key, desc in available_resources.items():
            print(f"  {key:<20} : {desc}")
        return

    regions = args.regions
    selected_resources = (
        set(args.selected_resources)
        if args.selected_resources
        else set(available_resources.keys())
    )

    print("🚀 AWS 리소스 조회 스크립트 시작")
    print("=" * 50)
    print(f"🌍 조회 리전: {', '.join(regions)}")

    if args.selected_resources:
        print(f"🎯 선택된 리소스: {', '.join(sorted(selected_resources))}")
    else:
        print("📋 모든 리소스를 조회합니다.")
    print()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    current_dir = os.path.dirname(__file__)
    data_dir = os.path.join(current_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    output_dir = os.path.join(data_dir, timestamp)
    os.makedirs(output_dir, exist_ok=True)

    all_raw_data = {}
    all_filtered_data = {}  # 필터링된 데이터를 저장할 딕셔너리
    excel_path = os.path.join(output_dir, "aws_resources.xlsx")
    writer = pd.ExcelWriter(excel_path, engine="openpyxl")

    for region in regions:
        print(f"\n=== Collecting resources in region: {region} ===")
        session = boto3.Session(region_name=region)
        region_raw_data = {}
        region_filtered_data = {}

        # --- EC2 ---
        if "ec2" in selected_resources:
            print("  🖥️  EC2 조회 중...")
            ec2_data_raw = ec2_raw(session, region)
            ec2_data_filtered = ec2_filtered(ec2_data_raw)
            region_raw_data["EC2"] = ec2_data_raw
            if not ec2_data_filtered.empty:
                region_filtered_data["EC2"] = ec2_data_filtered.to_dict("records")
                sheet_name = f"EC2_{region}"[:31]
                ec2_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- VPC ---
        if "vpc" in selected_resources:
            print("  🌐 VPC 조회 중...")
            vpc_data_raw = vpc_raw(session, region)
            vpc_data_filtered = vpc_filtered(vpc_data_raw)
            region_raw_data["VPC"] = vpc_data_raw
            if not vpc_data_filtered.empty:
                region_filtered_data["VPC"] = vpc_data_filtered.to_dict("records")
                sheet_name = f"VPC_{region}"[:31]
                vpc_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- RDS ---
        if "rds" in selected_resources:
            print("  🗄️  RDS 조회 중...")
            rds_data_raw = rds_raw(session, region)
            rds_data_filtered = rds_filtered(rds_data_raw)
            region_raw_data["RDS"] = rds_data_raw
            if not rds_data_filtered.empty:
                region_filtered_data["RDS"] = rds_data_filtered.to_dict("records")
                sheet_name = f"RDS_{region}"[:31]
                rds_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- EKS ---
        if "eks" in selected_resources:
            print("  ☸️  EKS 조회 중...")
            eks_data_raw = eks_raw(session, region)
            eks_data_filtered = eks_filtered(eks_data_raw)
            region_raw_data["EKS"] = eks_data_raw
            if not eks_data_filtered.empty:
                region_filtered_data["EKS"] = eks_data_filtered.to_dict("records")
                sheet_name = f"EKS_{region}"[:31]
                eks_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- Subnets ---
        if "subnets" in selected_resources:
            print("  🔗 Subnets 조회 중...")
            subnets_data_raw = subnets_raw(session, region)
            subnets_data_filtered = subnets_filtered(subnets_data_raw)
            region_raw_data["Subnets"] = subnets_data_raw
            if not subnets_data_filtered.empty:
                region_filtered_data["Subnets"] = subnets_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"Subnets_{region}"[:31]
                subnets_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- DynamoDB ---
        if "dynamodb" in selected_resources:
            print("  📊 DynamoDB 조회 중...")
            dynamodb_data_raw = dynamodb_raw(session, region)
            dynamodb_data_filtered = dynamodb_filtered(dynamodb_data_raw)
            region_raw_data["DynamoDB"] = dynamodb_data_raw
            if not dynamodb_data_filtered.empty:
                region_filtered_data["DynamoDB"] = dynamodb_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"DynamoDB_{region}"[:31]
                dynamodb_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- ELB (Classic, ALB, NLB) ---
        if "elb" in selected_resources:
            print("  ⚖️  ELB 조회 중...")
            elb_data_raw = elb_raw(session, region)
            elb_data_filtered = elb_filtered(elb_data_raw)
            region_raw_data["ELB"] = elb_data_raw
            if not elb_data_filtered.empty:
                region_filtered_data["ELB"] = elb_data_filtered.to_dict("records")
                sheet_name = f"ELB_{region}"[:31]
                elb_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- ElastiCache ---
        if "elasticache" in selected_resources:
            print("  🚀 ElastiCache 조회 중...")
            elasticache_data_raw = elasticache_raw(session, region)
            elasticache_data_filtered = elasticache_filtered(elasticache_data_raw)
            region_raw_data["ElastiCache"] = elasticache_data_raw
            if not elasticache_data_filtered.empty:
                region_filtered_data["ElastiCache"] = elasticache_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"ElastiCache_{region}"[:31]
                elasticache_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- EBS Volumes ---
        if "ebs" in selected_resources:
            print("  💾 EBS Volumes 조회 중...")
            ebs_data_raw = ebs_raw(session, region)
            ebs_data_filtered = ebs_filtered(ebs_data_raw)
            region_raw_data["EBS_Volumes"] = ebs_data_raw
            if not ebs_data_filtered.empty:
                region_filtered_data["EBS_Volumes"] = ebs_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"EBS_Volumes_{region}"[:31]
                ebs_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- EBS Snapshot ---
        if "ebs_snapshot" in selected_resources:
            print("  📸 EBS Snapshots 조회 중...")
            ebs_snapshot_data_raw = ebs_snapshot_raw(session, region)
            ebs_snapshot_data_filtered = ebs_snapshot_filtered(ebs_snapshot_data_raw)
            region_raw_data["EBS_Snapshot"] = ebs_snapshot_data_raw
            if not ebs_snapshot_data_filtered.empty:
                region_filtered_data["EBS_Snapshot"] = (
                    ebs_snapshot_data_filtered.to_dict("records")
                )
                sheet_name = f"EBS_Snapshot_{region}"[:31]
                ebs_snapshot_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- AMIs (Owner=self) ---
        if "amis" in selected_resources:
            print("  🖼️  AMIs 조회 중...")
            amis_data_raw = amis_raw(session, region)
            amis_data_filtered = amis_filtered(amis_data_raw)
            region_raw_data["AMIs"] = amis_data_raw
            if not amis_data_filtered.empty:
                region_filtered_data["AMIs"] = amis_data_filtered.to_dict("records")
                sheet_name = f"AMIs_{region}"[:31]
                amis_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- NAT Gateway ---
        if "nat_gateway" in selected_resources:
            print("  🌉 NAT Gateway 조회 중...")
            nat_gateway_data_raw = nat_gateway_raw(session, region)
            nat_gateway_data_filtered = nat_gateway_filtered(nat_gateway_data_raw)
            region_raw_data["NAT_Gateway"] = nat_gateway_data_raw
            if not nat_gateway_data_filtered.empty:
                region_filtered_data["NAT_Gateway"] = nat_gateway_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"NAT_{region}"[:31]
                nat_gateway_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- VPC Endpoints ---
        if "vpc_endpoint" in selected_resources:
            print("  🔌 VPC Endpoints 조회 중...")
            vpc_endpoint_data_raw = vpc_endpoint_raw(session, region)
            vpc_endpoint_data_filtered = vpc_endpoint_filtered(vpc_endpoint_data_raw)
            region_raw_data["VPC_Endpoints"] = vpc_endpoint_data_raw
            if not vpc_endpoint_data_filtered.empty:
                region_filtered_data["VPC_Endpoints"] = (
                    vpc_endpoint_data_filtered.to_dict("records")
                )
                sheet_name = f"VpcEP_{region}"[:31]
                vpc_endpoint_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Kinesis Data Streams ---
        if "kinesis_streams" in selected_resources:
            print("  🌊 Kinesis Streams 조회 중...")
            kinesis_streams_data_raw = kinesis_streams_raw(session, region)
            kinesis_streams_data_filtered = kinesis_streams_filtered(
                kinesis_streams_data_raw
            )
            region_raw_data["KinesisStreams"] = kinesis_streams_data_raw
            if not kinesis_streams_data_filtered.empty:
                region_filtered_data["KinesisStreams"] = (
                    kinesis_streams_data_filtered.to_dict("records")
                )
                sheet_name = f"KinesisStreams_{region}"[:31]
                kinesis_streams_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Glue Job ---
        if "glue_job" in selected_resources:
            print("  🔧 Glue Jobs 조회 중...")
            glue_job_data_raw = glue_job_raw(session, region)
            glue_job_data_filtered = glue_job_filtered(glue_job_data_raw)
            region_raw_data["GlueJob"] = glue_job_data_raw
            if not glue_job_data_filtered.empty:
                region_filtered_data["GlueJob"] = glue_job_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"GlueJob_{region}"[:31]
                glue_job_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Kinesis Data Firehose ---
        if "kinesis_firehose" in selected_resources:
            print("  🚒 Kinesis Firehose 조회 중...")
            kinesis_firehose_data_raw = kinesis_firehose_raw(session, region)
            kinesis_firehose_data_filtered = kinesis_firehose_filtered(
                kinesis_firehose_data_raw
            )
            region_raw_data["KinesisFirehose"] = kinesis_firehose_data_raw
            if not kinesis_firehose_data_filtered.empty:
                region_filtered_data["KinesisFirehose"] = (
                    kinesis_firehose_data_filtered.to_dict("records")
                )
                sheet_name = f"KinesisFirehose_{region}"[:31]
                kinesis_firehose_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Secrets Manager ---
        if "secrets_manager" in selected_resources:
            print("  🔐 Secrets Manager 조회 중...")
            secrets_data_raw = secrets_raw(session, region)
            secrets_data_filtered = secrets_filtered(secrets_data_raw)
            region_raw_data["SecretsManager"] = secrets_data_raw
            if not secrets_data_filtered.empty:
                region_filtered_data["SecretsManager"] = secrets_data_filtered.to_dict(
                    "records"
                )
                sheet_name = f"Secrets_{region}"[:31]
                secrets_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Elastic IP ---
        if "eip" in selected_resources:
            print("  🌐 Elastic IP 조회 중...")
            eip_data_raw = eip_raw(session, region)
            eip_data_filtered = eip_filtered(eip_data_raw)
            region_raw_data["EIP"] = eip_data_raw
            if not eip_data_filtered.empty:
                region_filtered_data["EIP"] = eip_data_filtered.to_dict("records")
                sheet_name = f"EIP_{region}"[:31]
                eip_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- Internet Gateway ---
        if "internet_gateway" in selected_resources:
            print("  🌍 Internet Gateway 조회 중...")
            internet_gateway_data_raw = internet_gateway_raw(session, region)
            internet_gateway_data_filtered = internet_gateway_filtered(
                internet_gateway_data_raw
            )
            region_raw_data["InternetGateway"] = internet_gateway_data_raw
            if not internet_gateway_data_filtered.empty:
                region_filtered_data["InternetGateway"] = (
                    internet_gateway_data_filtered.to_dict("records")
                )
                sheet_name = f"IGW_{region}"[:31]
                internet_gateway_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Security Groups ---
        if "security_groups" in selected_resources:
            print("  🛡️  Security Groups 조회 중...")
            security_groups_data_raw = security_groups_raw(session, region)
            security_groups_data_filtered = security_groups_filtered(
                security_groups_data_raw
            )
            region_raw_data["SecurityGroups"] = security_groups_data_raw
            if not security_groups_data_filtered.empty:
                region_filtered_data["SecurityGroups"] = (
                    security_groups_data_filtered.to_dict("records")
                )
                sheet_name = f"SG_{region}"[:31]
                security_groups_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- ECR ---
        if "ecr" in selected_resources:
            print("  📦 ECR 조회 중...")
            ecr_data_raw = ecr_raw(session, region)
            ecr_data_filtered = ecr_filtered(ecr_data_raw)
            region_raw_data["ECR"] = ecr_data_raw
            if not ecr_data_filtered.empty:
                region_filtered_data["ECR"] = ecr_data_filtered.to_dict("records")
                sheet_name = f"ECR_{region}"[:31]
                ecr_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

        # --- Security Group Rules ---
        if "security_group_rules" in selected_resources:
            print("  📋 Security Group Rules 조회 중...")
            security_group_rules_data_raw = security_group_rules_raw(session, region)
            security_group_rules_data_filtered = security_group_rules_filtered(
                security_group_rules_data_raw
            )
            region_raw_data["SecurityGroupRules"] = security_group_rules_data_raw
            if not security_group_rules_data_filtered.empty:
                region_filtered_data["SecurityGroupRules"] = (
                    security_group_rules_data_filtered.to_dict("records")
                )
                sheet_name = f"SGRules_{region}"[:31]
                security_group_rules_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- Auto Scaling Groups ---
        if "auto_scaling_groups" in selected_resources:
            print("  📈 Auto Scaling Groups 조회 중...")
            auto_scaling_groups_data_raw = auto_scaling_groups_raw(session, region)
            auto_scaling_groups_data_filtered = auto_scaling_groups_filtered(
                auto_scaling_groups_data_raw
            )
            region_raw_data["AutoScalingGroups"] = auto_scaling_groups_data_raw
            if not auto_scaling_groups_data_filtered.empty:
                region_filtered_data["AutoScalingGroups"] = (
                    auto_scaling_groups_data_filtered.to_dict("records")
                )
                sheet_name = f"ASG_{region}"[:31]
                auto_scaling_groups_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        # --- SES Identity (Email) ---
        if "ses_identity" in selected_resources:
            print("  📧 SES Identity 조회 중...")
            ses_identity_data_raw = ses_identity_raw(session, region)
            ses_identity_data_filtered = ses_identity_filtered(ses_identity_data_raw)
            region_raw_data["SESIdentity"] = ses_identity_data_raw
            if not ses_identity_data_filtered.empty:
                region_filtered_data["SESIdentity"] = (
                    ses_identity_data_filtered.to_dict("records")
                )
                sheet_name = f"SESIdentity_{region}"[:31]
                ses_identity_data_filtered.to_excel(
                    writer, sheet_name=sheet_name, index=False
                )

        all_raw_data[region] = region_raw_data
        all_filtered_data[region] = region_filtered_data

    # --- S3 Buckets (Global) ---
    if "s3" in selected_resources:
        print("\n🪣 S3 Buckets (글로벌) 조회 중...")
        s3_session = boto3.Session(region_name="us-east-1")
        s3_data_raw = s3_raw(s3_session)
        s3_data_filtered = s3_filtered(s3_data_raw)
        all_raw_data["S3"] = s3_data_raw
        if not s3_data_filtered.empty:
            all_filtered_data["S3"] = s3_data_filtered.to_dict("records")
            s3_data_filtered.to_excel(writer, sheet_name="S3", index=False)

    # --- Global Accelerator (Global) ---
    if "global_accelerator" in selected_resources:
        print("\n🚀 Global Accelerator (글로벌) 조회 중...")
        ga_session = boto3.Session(region_name="us-west-2")
        ga_data_raw = ga_raw(ga_session, "us-west-2")
        ga_data_filtered = ga_filtered(ga_data_raw)
        all_raw_data["GlobalAccelerator"] = ga_data_raw
        if not ga_data_filtered.empty:
            all_filtered_data["GlobalAccelerator"] = ga_data_filtered.to_dict("records")
            ga_data_filtered.to_excel(
                writer, sheet_name="GlobalAccelerator", index=False
            )

    # --- Route53 HostedZone (global) ---
    if "route53" in selected_resources:
        print("\n🌐 Route53 HostedZones (글로벌) 조회 중...")
        route53_session = boto3.Session()  # 글로벌 서비스
        route53_data_raw = route53_raw(route53_session, None)
        route53_data_filtered = route53_filtered(route53_data_raw)
        all_raw_data["Route53"] = route53_data_raw
        if not route53_data_filtered.empty:
            all_filtered_data["Route53"] = route53_data_filtered.to_dict("records")
            sheet_name = "Route53"
            route53_data_filtered.to_excel(writer, sheet_name=sheet_name, index=False)

    writer.close()
    print(f"\n📊 Excel 파일 생성 완료: {excel_path}")

    csv_path = os.path.join(output_dir, "aws_resources.csv")
    csv_rows = _build_csv_rows(all_filtered_data)
    csv_df = pd.DataFrame(csv_rows)
    if csv_df.empty:
        csv_df = pd.DataFrame(columns=["Region", "ResourceType"])
    csv_df.to_csv(csv_path, index=False)
    print(f"📄 CSV 파일 생성 완료: {csv_path}")

    json_path = os.path.join(output_dir, "aws_resources.json")
    json_payload = {
        "metadata": {
            "generatedAt": datetime.now(timezone.utc),
            "timestamp": timestamp,
            "regions": regions,
            "resources": sorted(selected_resources),
        },
        "raw": all_raw_data,
        "filtered": all_filtered_data,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
    print(f"📄 JSON 파일 생성 완료: {json_path}")

    # 요약 정보 출력
    print("\n✅ AWS 리소스 조회 완료!")
    print(f"🌍 조회된 리전: {', '.join(regions)}")
    if args.selected_resources:
        print(f"🎯 조회된 리소스: {', '.join(sorted(selected_resources))}")
    else:
        print("📋 모든 리소스가 조회되었습니다.")

    # 각 리전별 조회된 리소스 수 계산
    total_resources = 0
    for region, region_data in all_filtered_data.items():
        if region not in ["S3", "GlobalAccelerator", "Route53"]:  # 글로벌 리소스 제외
            resource_count = sum(len(resources) for resources in region_data.values())
            if resource_count > 0:
                print(f"  📍 {region}: {resource_count}개 리소스")
                total_resources += resource_count

    # 글로벌 리소스 수 계산
    global_resources = 0
    for global_service in ["S3", "GlobalAccelerator", "Route53"]:
        if global_service in all_filtered_data:
            count = len(all_filtered_data[global_service])
            if count > 0:
                print(f"  🌐 {global_service}: {count}개 리소스")
                global_resources += count

    print(f"📊 총 조회된 리소스: {total_resources + global_resources}개")

    # Security Groups만 선택된 경우 상세 보안 분석 출력
    if selected_resources == {"security_groups"}:
        print_security_groups_analysis(all_filtered_data)


if __name__ == "__main__":
    main()
