"""
Tests for security groups resource module.
"""

import sys
from unittest.mock import MagicMock, patch

import pandas as pd
from botocore.exceptions import ClientError

sys.path.insert(0, ".")

from resources.security_groups import get_filtered_data, get_raw_data


class TestSecurityGroups:
    """Test cases for security groups module."""

    def test_get_raw_data_success(self):
        """Test successful retrieval of security groups data."""
        # Mock session and client
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Mock response data
        mock_response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-12345678",
                    "GroupName": "test-sg",
                    "VpcId": "vpc-12345678",
                    "Description": "Test security group",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                    "IpPermissionsEgress": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                    "Tags": [{"Key": "Name", "Value": "test-sg"}],
                }
            ]
        }

        mock_client.describe_security_groups.return_value = mock_response

        with patch(
            "resources.security_groups._collect_security_group_usage",
            return_value={"sg-12345678": ["EC2Instance:i-001"]},
        ):
            result = get_raw_data(mock_session, "us-east-1")

        # Assertions
        assert len(result) == 1
        assert result[0]["GroupId"] == "sg-12345678"
        assert result[0]["HasAnyOpenInbound"] is True
        assert result[0]["AttachedResources"] == ["EC2Instance:i-001"]
        mock_client.describe_security_groups.assert_called_once()

    def test_get_raw_data_ipv6_any_open(self):
        """Test security group with IPv6 ::/0 inbound rule."""
        # Mock session and client
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Mock response data with IPv6 ::/0
        mock_response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-ipv6-open",
                    "GroupName": "ipv6-open-sg",
                    "VpcId": "vpc-12345678",
                    "Description": "IPv6 open security group",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                }
            ]
        }

        mock_client.describe_security_groups.return_value = mock_response

        with patch(
            "resources.security_groups._collect_security_group_usage",
            return_value={"sg-ipv6-open": []},
        ):
            result = get_raw_data(mock_session, "us-east-1")

        # Assertions
        assert len(result) == 1
        assert result[0]["GroupId"] == "sg-ipv6-open"
        assert result[0]["HasAnyOpenInbound"] is True

    def test_get_raw_data_no_any_open_inbound(self):
        """Test security group without 0.0.0.0/0 or ::/0 inbound rule."""
        # Mock session and client
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Mock response data without 0.0.0.0/0 or ::/0
        mock_response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-87654321",
                    "GroupName": "secure-sg",
                    "VpcId": "vpc-87654321",
                    "Description": "Secure security group",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                }
            ]
        }

        mock_client.describe_security_groups.return_value = mock_response

        with patch(
            "resources.security_groups._collect_security_group_usage",
            return_value={"sg-87654321": []},
        ):
            result = get_raw_data(mock_session, "us-east-1")

        # Assertions
        assert len(result) == 1
        assert result[0]["GroupId"] == "sg-87654321"
        assert result[0]["HasAnyOpenInbound"] is False

    def test_get_raw_data_with_pagination(self):
        """Test handling of paginated responses."""
        # Mock session and client
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Mock paginated responses
        first_response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-page1",
                    "GroupName": "page1-sg",
                    "VpcId": "vpc-12345678",
                    "Description": "Page 1 security group",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                }
            ],
            "NextToken": "token123",
        }

        second_response = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-page2",
                    "GroupName": "page2-sg",
                    "VpcId": "vpc-87654321",
                    "Description": "Page 2 security group",
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                }
            ]
        }

        mock_client.describe_security_groups.side_effect = [
            first_response,
            second_response,
        ]

        with patch(
            "resources.security_groups._collect_security_group_usage",
            return_value={
                "sg-page1": ["EC2Instance:i-page1"],
                "sg-page2": [],
            },
        ):
            result = get_raw_data(mock_session, "us-east-1")

        # Assertions
        assert len(result) == 2
        assert result[0]["GroupId"] == "sg-page1"
        assert result[1]["GroupId"] == "sg-page2"
        assert mock_client.describe_security_groups.call_count == 2

    def test_get_raw_data_client_error(self):
        """Test handling of client errors."""
        # Mock session and client
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Mock client error
        mock_client.describe_security_groups.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeSecurityGroups",
        )

        with patch(
            "resources.security_groups._collect_security_group_usage",
            return_value={},
        ):
            result = get_raw_data(mock_session, "us-east-1")

        # Assertions
        assert result == []

    def test_get_raw_data_unexpected_error(self):
        """Test handling of unexpected errors."""
        # Mock session and client
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        # Mock unexpected error
        mock_client.describe_security_groups.side_effect = Exception("Unexpected error")

        with patch(
            "resources.security_groups._collect_security_group_usage",
            return_value={},
        ):
            result = get_raw_data(mock_session, "us-east-1")

        # Assertions
        assert result == []

    def test_get_filtered_data_empty_input(self):
        """Test filtering with empty input."""
        result = get_filtered_data([])
        assert isinstance(result, pd.DataFrame)
        assert result.empty

    def test_get_filtered_data_complete_sg(self):
        """Test filtering with complete security group data."""
        raw_data = [
            {
                "GroupId": "sg-12345678",
                "GroupName": "test-sg",
                "VpcId": "vpc-12345678",
                "Description": "Test security group",
                "HasAnyOpenInbound": True,
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0", "Description": "HTTP access"}
                        ],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "UserIdGroupPairs": [
                            {
                                "GroupId": "sg-87654321",
                                "Description": "SSH from admin SG",
                            }
                        ],
                    },
                ],
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
                "Tags": [
                    {"Key": "Name", "Value": "test-sg"},
                    {"Key": "Environment", "Value": "dev"},
                ],
                "AttachedResources": ["EC2Instance:i-001"],
            }
        ]

        result = get_filtered_data(raw_data)

        # Assertions
        assert len(result) == 1
        assert result.iloc[0]["SecurityGroupId"] == "sg-12345678"
        assert result.iloc[0]["SecurityGroupName"] == "test-sg"
        assert result.iloc[0]["VpcId"] == "vpc-12345678"
        assert result.iloc[0]["Description"] == "Test security group"
        assert result.iloc[0]["AnyOpenInbound"] == "⚠️ YES"
        assert "Name=test-sg, Environment=dev" in result.iloc[0]["Tags"]
        assert result.iloc[0]["AttachedResources"] == ["EC2Instance:i-001"]
        assert result.iloc[0]["AttachedResourceCount"] == 1

        # Check inbound rules formatting
        inbound_rules = result.iloc[0]["InboundRules"]
        assert isinstance(inbound_rules, list)
        assert len(inbound_rules) == 2
        assert "tcp:80 from 0.0.0.0/0 (HTTP access)" in inbound_rules
        assert "tcp:22 from sg-87654321 (SSH from admin SG)" in inbound_rules

        # Check outbound rules formatting
        outbound_rules = result.iloc[0]["OutboundRules"]
        assert isinstance(outbound_rules, list)
        assert len(outbound_rules) == 1
        assert "All:All to 0.0.0.0/0" in outbound_rules

    def test_get_filtered_data_ipv6_and_prefix_lists(self):
        """Test filtering with IPv6 ranges and prefix lists."""
        raw_data = [
            {
                "GroupId": "sg-advanced",
                "GroupName": "advanced-sg",
                "VpcId": "vpc-12345678",
                "Description": "Advanced security group",
                "HasAnyOpenInbound": False,
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "Ipv6Ranges": [
                            {"CidrIpv6": "2001:db8::/32", "Description": "IPv6 HTTPS"}
                        ],
                        "PrefixListIds": [
                            {
                                "PrefixListId": "pl-12345678",
                                "Description": "S3 prefix list",
                            }
                        ],
                    }
                ],
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }
                ],
                "Tags": [],
                "AttachedResources": [],
            }
        ]

        result = get_filtered_data(raw_data)

        # Assertions
        inbound_rules = result.iloc[0]["InboundRules"]
        assert "tcp:443 from 2001:db8::/32 (IPv6 HTTPS)" in inbound_rules
        assert "tcp:443 from pl-12345678 (S3 prefix list)" in inbound_rules

        outbound_rules = result.iloc[0]["OutboundRules"]
        assert "tcp:80 to ::/0" in outbound_rules

    def test_get_filtered_data_port_ranges(self):
        """Test filtering with different port range scenarios."""
        raw_data = [
            {
                "GroupId": "sg-ports",
                "GroupName": "port-test-sg",
                "VpcId": "vpc-12345678",
                "Description": "Port range test",
                "HasAnyOpenInbound": False,
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 8080,
                        "ToPort": 8090,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    },
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "192.168.1.0/24"}],
                    },
                ],
                "IpPermissionsEgress": [],
                "Tags": [],
                "AttachedResources": [],
            }
        ]

        result = get_filtered_data(raw_data)

        # Assertions
        inbound_rules = result.iloc[0]["InboundRules"]
        assert "tcp:8080-8090 from 10.0.0.0/8" in inbound_rules
        assert "All:All from 192.168.1.0/24" in inbound_rules

    def test_get_filtered_data_no_rules(self):
        """Test filtering with security group having no rules."""
        raw_data = [
            {
                "GroupId": "sg-empty",
                "GroupName": "empty-sg",
                "VpcId": "vpc-12345678",
                "Description": "Empty security group",
                "HasAnyOpenInbound": False,
                "IpPermissions": [],
                "IpPermissionsEgress": [],
                "Tags": [],
                "AttachedResources": [],
            }
        ]

        result = get_filtered_data(raw_data)

        # Assertions
        assert len(result) == 1
        assert result.iloc[0]["SecurityGroupId"] == "sg-empty"
        assert result.iloc[0]["AnyOpenInbound"] == "No"
        assert result.iloc[0]["InboundRules"] == []
        assert result.iloc[0]["OutboundRules"] == []
        assert result.iloc[0]["Tags"] == ""

    def test_get_filtered_data_missing_fields(self):
        """Test filtering with missing optional fields."""
        raw_data = [
            {
                "GroupId": "sg-minimal",
                "HasAnyOpenInbound": False,
                "IpPermissions": [],
                "IpPermissionsEgress": [],
            }
        ]

        result = get_filtered_data(raw_data)

        # Assertions
        assert len(result) == 1
        assert result.iloc[0]["SecurityGroupId"] == "sg-minimal"
        assert result.iloc[0]["SecurityGroupName"] == ""
        assert result.iloc[0]["VpcId"] == ""
        assert result.iloc[0]["Description"] == ""
        assert result.iloc[0]["Tags"] == ""
        assert result.iloc[0]["AttachedResourceCount"] == 0

    def test_get_filtered_data_empty_tags(self):
        """Test filtering with empty tags."""
        raw_data = [
            {
                "GroupId": "sg-no-tags",
                "GroupName": "no-tags-sg",
                "VpcId": "vpc-12345678",
                "Description": "No tags security group",
                "HasAnyOpenInbound": False,
                "IpPermissions": [],
                "IpPermissionsEgress": [],
                "Tags": [],
            }
        ]

        result = get_filtered_data(raw_data)

        # Assertions
        assert result.iloc[0]["Tags"] == ""
