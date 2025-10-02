import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from listup_aws_resources import _build_csv_rows, main


@patch("pandas.DataFrame.to_csv")
@patch("json.dump")
@patch("pandas.ExcelWriter")
@patch("boto3.Session")
def test_main(mock_session, mock_excel_writer, mock_json_dump, mock_to_csv):
    # Mock the boto3 session and client
    mock_client = MagicMock()
    mock_client.list_streams.return_value = {"StreamNames": [], "HasMoreStreams": False}
    mock_client.list_delivery_streams.return_value = {
        "DeliveryStreamNames": [],
        "HasMoreDeliveryStreams": False,
    }
    mock_session.return_value.client.return_value = mock_client

    writer_mock = MagicMock()
    mock_excel_writer.return_value = writer_mock

    try:
        main()
    except Exception as e:
        pytest.fail(f"main() raised an exception: {e}")

    writer_mock.close.assert_called_once()
    mock_to_csv.assert_called_once()
    mock_json_dump.assert_called_once()


def test_build_csv_rows_handles_nested_values():
    filtered_data = {
        "ap-northeast-2": {
            "SecurityGroups": [
                {
                    "SecurityGroupId": "sg-123",
                    "AttachedResources": ["EC2Instance:i-1", "Lambda:fn"],
                    "InboundRules": ["tcp:80 from 0.0.0.0/0"],
                    "Tags": "Name=demo",
                }
            ]
        },
        "S3": [
            {
                "Name": "bucket-1",
                "Region": "us-east-1",
            }
        ],
    }

    rows = _build_csv_rows(filtered_data)

    assert len(rows) == 2

    sg_row = next(row for row in rows if row["ResourceType"] == "SecurityGroups")
    assert sg_row["Region"] == "ap-northeast-2"
    assert sg_row["AttachedResources"] == "EC2Instance:i-1; Lambda:fn"
    assert sg_row["InboundRules"] == "tcp:80 from 0.0.0.0/0"

    s3_row = next(row for row in rows if row["ResourceType"] == "S3")
    assert s3_row["Region"] == "Global"
    assert s3_row["Name"] == "bucket-1"
    assert s3_row["RecordRegion"] == "us-east-1"
