"""AWS Security Groups resource module.

이 모듈은 Security Group 원본 데이터를 수집하고, 인바운드/아웃바운드 규칙뿐 아니라
해당 Security Group을 실제로 사용 중인 리소스까지 추적해 필터링된 결과를 반환한다.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
from botocore.exceptions import ClientError


def get_raw_data(session: Any, region: str) -> list[dict[str, Any]]:
    """
    AWS Security Group 리소스 정보를 조회합니다.

    Args:
        session: boto3 세션 객체
        region: AWS 리전명

    Returns:
        list: Security Group 리소스 정보 목록
    """
    try:
        ec2_client = session.client("ec2")
        response = ec2_client.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])

        # 추가 페이지가 있는 경우 모두 조회
        while "NextToken" in response:
            response = ec2_client.describe_security_groups(
                NextToken=response["NextToken"]
            )
            security_groups.extend(response.get("SecurityGroups", []))

        # 각 보안 그룹에 대해 0.0.0.0/0 AnyOpen 여부 확인
        for sg in security_groups:
            sg["HasAnyOpenInbound"] = _check_any_open_inbound(sg)

        usage_map = _collect_security_group_usage(
            session=session,
            region=region,
            security_groups=security_groups,
            ec2_client=ec2_client,
        )

        for sg in security_groups:
            group_id = sg.get("GroupId")
            sg["AttachedResources"] = usage_map.get(group_id, [])

        return security_groups
    except ClientError as e:
        print(f"Error fetching security groups in {region}: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error fetching security groups in {region}: {e}")
        return []


def _check_any_open_inbound(sg: dict[str, Any]) -> bool:
    """
    보안 그룹에 0.0.0.0/0 또는 ::/0 인바운드 규칙이 있는지 확인합니다.

    Args:
        sg: 보안 그룹 데이터

    Returns:
        bool: AnyOpen 인바운드 규칙 존재 여부
    """
    for rule in sg.get("IpPermissions", []):
        # IPv4 범위 확인
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return True

        # IPv6 범위 확인
        for ipv6_range in rule.get("Ipv6Ranges", []):
            if ipv6_range.get("CidrIpv6") == "::/0":
                return True

    return False


def get_filtered_data(raw_data: list[dict[str, Any]]) -> pd.DataFrame:
    """
    원시 Security Group 데이터를 필터링하여 필요한 정보만 추출합니다.

    Args:
        raw_data: Security Group 원시 데이터

    Returns:
        DataFrame: 필터링된 Security Group 데이터
    """
    if not raw_data:
        return pd.DataFrame()

    filtered_data = []

    for sg in raw_data:
        # 인바운드 규칙 문자열로 변환
        inbound_rules = _format_rules(sg.get("IpPermissions", []), "from")

        # 아웃바운드 규칙 문자열로 변환
        outbound_rules = _format_rules(sg.get("IpPermissionsEgress", []), "to")

        # 필터링된 데이터 생성
        filtered_sg = {
            "SecurityGroupId": sg.get("GroupId", ""),
            "SecurityGroupName": sg.get("GroupName", ""),
            "VpcId": sg.get("VpcId", ""),
            "Description": sg.get("Description", ""),
            "AnyOpenInbound": "⚠️ YES" if sg.get("HasAnyOpenInbound", False) else "No",
            "InboundRules": inbound_rules,
            "OutboundRules": outbound_rules,
            "Tags": _format_tags(sg.get("Tags", [])),
            "AttachedResources": sg.get("AttachedResources", []),
            "AttachedResourceCount": len(sg.get("AttachedResources", [])),
        }

        filtered_data.append(filtered_sg)

    return pd.DataFrame(filtered_data)


def _collect_security_group_usage(
    *,
    session: Any,
    region: str,
    security_groups: list[dict[str, Any]],
    ec2_client: Any,
) -> dict[str, list[str]]:
    """Security Group이 연결된 리소스를 추적한다.

    Args:
        session: boto3 세션 객체
        region: 조회 리전
        security_groups: 조회된 Security Group 원본 데이터
        ec2_client: EC2 클라이언트 (재사용)

    Returns:
        dict: Security Group ID를 키로 가지는 사용 리소스 목록 매핑
    """

    if not security_groups:
        return {}

    usage_map: dict[str, set[str]] = {
        sg.get("GroupId", ""): set() for sg in security_groups if sg.get("GroupId")
    }
    if not usage_map:
        return {}

    vpc_map = {sg.get("GroupId", ""): sg.get("VpcId") for sg in security_groups}

    _collect_from_network_interfaces(ec2_client, usage_map)

    collectors = (
        lambda: _collect_from_elbv2(session, usage_map),
        lambda: _collect_from_elb(session, usage_map),
        lambda: _collect_from_rds(session, usage_map),
        lambda: _collect_from_lambda(session, usage_map),
        lambda: _collect_from_eks(session, usage_map),
        lambda: _collect_from_ecs(session, usage_map),
        lambda: _collect_from_elasticache(session, usage_map),
        lambda: _collect_from_memorydb(session, usage_map),
        lambda: _collect_from_efs(session, usage_map),
        lambda: _collect_from_fsx(session, usage_map),
        lambda: _collect_from_redshift(session, usage_map),
        lambda: _collect_from_redshift_serverless(session, usage_map),
        lambda: _collect_from_opensearch(session, usage_map),
        lambda: _collect_from_vpc_endpoints(session, usage_map, vpc_map),
    )

    for collector in collectors:
        try:
            collector()
        except ClientError as exc:  # pragma: no cover - 방어적 처리
            print(f"Error collecting Security Group usage in {region}: {exc}")
        except Exception as exc:  # pragma: no cover - 방어적 처리
            print(
                f"Unexpected error while collecting Security Group usage in {region}: {exc}"
            )

    return {sg_id: sorted(resources) for sg_id, resources in usage_map.items()}


def _collect_from_network_interfaces(
    ec2_client: Any, usage_map: dict[str, set[str]]
) -> None:
    """ENI 수준에서 Security Group 사용 현황을 추적한다."""

    try:
        paginator = ec2_client.get_paginator("describe_network_interfaces")
    except Exception as exc:  # pragma: no cover - paginator 생성 실패 방어
        print(f"Failed to create network interface paginator: {exc}")
        return

    try:
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                groups = eni.get("Groups", [])
                if not groups:
                    continue

                resource_labels = _build_network_interface_labels(eni)

                for group in groups:
                    sg_id = group.get("GroupId")
                    if sg_id in usage_map:
                        for label in resource_labels:
                            _add_usage(usage_map, sg_id, label)
    except ClientError as exc:
        print(f"Error describing network interfaces: {exc}")
    except Exception as exc:  # pragma: no cover - 예상치 못한 오류 방어
        print(f"Unexpected error while processing network interfaces: {exc}")


def _build_network_interface_labels(eni: dict[str, Any]) -> list[str]:
    """Network Interface 데이터를 식별 가능한 라벨 목록으로 구성한다."""

    labels: set[str] = set()
    eni_id = eni.get("NetworkInterfaceId", "")
    interface_type = (eni.get("InterfaceType") or "").upper()
    description = eni.get("Description", "")
    attachment = eni.get("Attachment") or {}
    instance_id = attachment.get("InstanceId")

    if instance_id:
        labels.add(f"EC2Instance:{instance_id}")

    if interface_type:
        type_hint = {
            "NETWORK_LOAD_BALANCER": "NLB",
            "GATEWAY_LOAD_BALANCER": "GLB",
            "NAT_GATEWAY": "NatGateway",
            "LAMBDA": "LambdaENI",
            "VPC_ENDPOINT": "VPCEndpointENI",
        }.get(interface_type, interface_type.title())
        labels.add(f"{type_hint}:{eni_id or description}")

    if description and description not in {eni_id}:
        labels.add(f"ENI:{description}")

    if not labels:
        labels.add(f"ENI:{eni_id}")

    return sorted(labels)


def _collect_from_elbv2(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("elbv2")
    paginator = client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancers", []):
            resource = (
                f"{lb.get('Type', 'alb').upper()}:{lb.get('LoadBalancerName', '')}"
            )
            for sg_id in lb.get("SecurityGroups", []) or []:
                _add_usage(usage_map, sg_id, resource)


def _collect_from_elb(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("elb")
    paginator = client.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancerDescriptions", []):
            resource = f"CLB:{lb.get('LoadBalancerName', '')}"
            for sg_id in lb.get("SecurityGroups", []) or []:
                _add_usage(usage_map, sg_id, resource)


def _collect_from_rds(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("rds")

    for page in client.get_paginator("describe_db_instances").paginate():
        for db_instance in page.get("DBInstances", []):
            resource = f"RDSInstance:{db_instance.get('DBInstanceIdentifier', '')}"
            groups = [
                group.get("VpcSecurityGroupId")
                for group in db_instance.get("VpcSecurityGroups", [])
                if group.get("VpcSecurityGroupId")
            ]
            for sg_id in groups:
                _add_usage(usage_map, sg_id, resource)

    for page in client.get_paginator("describe_db_clusters").paginate():
        for cluster in page.get("DBClusters", []):
            resource = f"RDSCluster:{cluster.get('DBClusterIdentifier', '')}"
            groups = [
                group.get("VpcSecurityGroupId")
                for group in cluster.get("VpcSecurityGroups", [])
                if group.get("VpcSecurityGroupId")
            ]
            for sg_id in groups:
                _add_usage(usage_map, sg_id, resource)

    for page in client.get_paginator("describe_db_proxies").paginate():
        for proxy in page.get("DBProxies", []):
            resource = f"RDSProxy:{proxy.get('DBProxyName', '')}"
            for sg_id in proxy.get("VpcSecurityGroupIds", []) or []:
                _add_usage(usage_map, sg_id, resource)


def _collect_from_lambda(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("lambda")
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        for function in page.get("Functions", []):
            resource = f"Lambda:{function.get('FunctionName', '')}"
            vpc_config = function.get("VpcConfig") or {}
            for sg_id in vpc_config.get("SecurityGroupIds", []) or []:
                _add_usage(usage_map, sg_id, resource)


def _collect_from_eks(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("eks")
    for cluster_name in client.list_clusters().get("clusters", []):
        cluster = client.describe_cluster(name=cluster_name).get("cluster", {})
        resource = f"EKSCluster:{cluster_name}"
        vpc_config = cluster.get("resourcesVpcConfig") or {}
        sg_ids = set(vpc_config.get("securityGroupIds", []) or [])
        cluster_sg = vpc_config.get("clusterSecurityGroupId")
        if cluster_sg:
            sg_ids.add(cluster_sg)
        for sg_id in sg_ids:
            _add_usage(usage_map, sg_id, resource)


def _collect_from_ecs(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("ecs")
    cluster_arns = client.list_clusters().get("clusterArns", [])
    for cluster_arn in cluster_arns:
        services = client.list_services(cluster=cluster_arn).get("serviceArns", [])
        for chunk_start in range(0, len(services), 10):
            chunk = services[chunk_start : chunk_start + 10]
            described = client.describe_services(cluster=cluster_arn, services=chunk)
            for service in described.get("services", []):
                resource = f"ECSService:{service.get('serviceName', '')}"
                network_config = (service.get("networkConfiguration") or {}).get(
                    "awsvpcConfiguration", {}
                )
                for sg_id in network_config.get("securityGroups", []) or []:
                    _add_usage(usage_map, sg_id, resource)


def _collect_from_elasticache(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("elasticache")
    response = client.describe_cache_clusters(ShowCacheNodeInfo=True)
    for cluster in response.get("CacheClusters", []):
        resource = f"ElastiCache:{cluster.get('CacheClusterId', '')}"
        for sg in cluster.get("SecurityGroups", []) or []:
            sg_id = sg.get("SecurityGroupId")
            _add_usage(usage_map, sg_id, resource)


def _collect_from_memorydb(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("memorydb")
    response = client.describe_clusters()
    for cluster in response.get("Clusters", []):
        resource = f"MemoryDB:{cluster.get('Name', '')}"
        for sg_id in cluster.get("SecurityGroups", []) or []:
            _add_usage(usage_map, sg_id, resource)


def _collect_from_efs(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("efs")
    file_systems = client.describe_file_systems().get("FileSystems", [])
    for fs in file_systems:
        resource = f"EFS:{fs.get('FileSystemId', '')}"
        mount_targets = client.describe_mount_targets(
            FileSystemId=fs.get("FileSystemId")
        ).get("MountTargets", [])
        for mount_target in mount_targets:
            sg_ids = client.describe_mount_target_security_groups(
                MountTargetId=mount_target.get("MountTargetId")
            ).get("SecurityGroups", [])
            for sg_id in sg_ids:
                _add_usage(usage_map, sg_id, resource)


def _collect_from_fsx(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("fsx")
    response = client.describe_file_systems()
    for fs in response.get("FileSystems", []):
        resource = f"FSx{fs.get('FileSystemType', '')}:{fs.get('FileSystemId', '')}"
        for sg_id in fs.get("SecurityGroupIds", []) or []:
            _add_usage(usage_map, sg_id, resource)


def _collect_from_redshift(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("redshift")
    response = client.describe_clusters()
    for cluster in response.get("Clusters", []):
        resource = f"Redshift:{cluster.get('ClusterIdentifier', '')}"
        groups = [
            group.get("VpcSecurityGroupId")
            for group in cluster.get("VpcSecurityGroups", [])
            if group.get("VpcSecurityGroupId")
        ]
        for sg_id in groups:
            _add_usage(usage_map, sg_id, resource)


def _collect_from_redshift_serverless(
    session: Any, usage_map: dict[str, set[str]]
) -> None:
    client = session.client("redshift-serverless")
    response = client.list_workgroups()
    for workgroup in response.get("workgroups", []):
        resource = f"RedshiftServerless:{workgroup.get('workgroupName', '')}"
        for sg_id in workgroup.get("securityGroupIds", []) or []:
            _add_usage(usage_map, sg_id, resource)


def _collect_from_opensearch(session: Any, usage_map: dict[str, set[str]]) -> None:
    client = session.client("opensearch")
    response = client.list_domain_names()
    for domain in response.get("DomainNames", []):
        name = domain.get("DomainName")
        if not name:
            continue
        detail = client.describe_domain(DomainName=name).get("DomainStatus", {})
        resource = f"OpenSearch:{name}"
        sg_ids = (detail.get("VPCOptions") or {}).get("SecurityGroupIds", []) or []
        for sg_id in sg_ids:
            _add_usage(usage_map, sg_id, resource)


def _collect_from_vpc_endpoints(
    session: Any, usage_map: dict[str, set[str]], vpc_map: dict[str, str]
) -> None:
    unique_vpcs = {vpc_id for vpc_id in vpc_map.values() if vpc_id}
    if not unique_vpcs:
        return

    client = session.client("ec2")
    paginator = client.get_paginator("describe_vpc_endpoints")
    for page in paginator.paginate(
        Filters=[{"Name": "vpc-id", "Values": sorted(unique_vpcs)}]
    ):
        for endpoint in page.get("VpcEndpoints", []):
            if endpoint.get("VpcEndpointType") != "Interface":
                continue
            resource = f"VPCEndpoint:{endpoint.get('VpcEndpointId', '')}"
            group_ids = set(endpoint.get("SecurityGroupIds", []) or [])
            for group in endpoint.get("Groups", []) or []:
                group_id = group.get("GroupId")
                if group_id:
                    group_ids.add(group_id)
            for sg_id in group_ids:
                _add_usage(usage_map, sg_id, resource)


def _add_usage(
    usage_map: dict[str, set[str]], sg_id: str | None, resource: str | None
) -> None:
    """Security Group 사용 리소스 정보를 usage_map에 안전하게 추가한다."""

    if not sg_id or sg_id not in usage_map or not resource:
        return
    usage_map[sg_id].add(resource)


def _format_rules(rules: list[dict[str, Any]], direction: str) -> list[str]:
    """
    보안 그룹 규칙을 문자열 형태로 포맷팅합니다.

    Args:
        rules: 보안 그룹 규칙 목록
        direction: 규칙 방향 ("from" 또는 "to")

    Returns:
        list: 포맷팅된 규칙 문자열 목록
    """
    formatted_rules = []

    for rule in rules:
        protocol = rule.get("IpProtocol", "-1")
        if protocol == "-1":
            protocol = "All"

        from_port = rule.get("FromPort", "All")
        to_port = rule.get("ToPort", "All")

        # 포트 범위 표시
        port_range = "All"
        if from_port != "All" and to_port != "All":
            if from_port == to_port:
                port_range = str(from_port)
            else:
                port_range = f"{from_port}-{to_port}"

        # 모든 소스/대상 수집
        sources_destinations = []

        # IPv4 범위 처리
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            description = ip_range.get("Description", "")
            ip_text = cidr
            if description:
                ip_text += f" ({description})"
            sources_destinations.append(ip_text)

        # IPv6 범위 처리
        for ipv6_range in rule.get("Ipv6Ranges", []):
            cidr = ipv6_range.get("CidrIpv6", "")
            description = ipv6_range.get("Description", "")
            ip_text = cidr
            if description:
                ip_text += f" ({description})"
            sources_destinations.append(ip_text)

        # 보안 그룹 참조 처리
        for sg_ref in rule.get("UserIdGroupPairs", []):
            sg_id = sg_ref.get("GroupId", "")
            description = sg_ref.get("Description", "")
            sg_text = sg_id
            if description:
                sg_text += f" ({description})"
            sources_destinations.append(sg_text)

        # Prefix List ID 처리
        for prefix_list in rule.get("PrefixListIds", []):
            prefix_id = prefix_list.get("PrefixListId", "")
            description = prefix_list.get("Description", "")
            prefix_text = prefix_id
            if description:
                prefix_text += f" ({description})"
            sources_destinations.append(prefix_text)

        # 규칙 문자열 생성
        if sources_destinations:
            for source_dest in sources_destinations:
                formatted_rules.append(
                    f"{protocol}:{port_range} {direction} {source_dest}"
                )

    return formatted_rules


def _format_tags(tags: list[dict[str, str]]) -> str:
    """
    태그 목록을 문자열로 포맷팅합니다.

    Args:
        tags: 태그 목록

    Returns:
        str: 포맷팅된 태그 문자열
    """
    if not tags:
        return ""

    return ", ".join([f"{tag.get('Key', '')}={tag.get('Value', '')}" for tag in tags])
