import argparse
import gzip
import importlib.util
import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("d1_collector", ROOT / "runner/collect_d1_runtime.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def arguments(directory):
    return argparse.Namespace(
        terraform_output_json=str(ROOT / "fixtures/d1-runtime-collector.example.json"), output_root=str(directory),
        region="ap-northeast-2", account_id="111111111111", aws_profile=None, hostname="argus-base.ar0nica.xyz",
        path="/d1/observe", client_cidr="8.8.8.8/32", client_ipv4="8.8.8.8", run_id="ARGUS-20260813-BASE-R01", request_id="ARGUS-20260813-BASE-R01-BEN-D1-OBS-001",
        trace_id="Root=1-66bad000-0123456789abcdef01234567", ssm_parameter_name="/argus/base/d1-canary",
        canary_bucket="argus-base-canary", canary_object_key="d1/canary.txt", canary_object_version_id="v1",
        host_id="i-0123456789abcdef0", host_process="argus-web", flow_eni_id="eni-0123456789abcdef0", flow_srcaddr="10.0.10.10", flow_dstaddr="10.0.20.10", flow_dstport=3306,
        redaction_key_file=str(directory / "hmac.key"), fixture_id="BEN-D1-OBS-001", concurrency=1,
        minimum_interval_seconds=1, request_timeout_seconds=1, poll_interval_seconds=1, poll_timeout_seconds=1,
        cli_timeout_seconds=1,
    )


class D1RuntimeCollectorTests(unittest.TestCase):
    def test_terraform_output_parser_maps_only_required_native_locations(self):
        args = arguments(ROOT)
        configuration = collector.collector_config(collector.terraform_values(args.terraform_output_json), args)
        self.assertEqual(configuration["groups"]["flow_logs"], "/argus/base/vpc-flow")
        self.assertEqual(configuration["rds_general"], "/aws/rds/instance/argus-base-mysql/general")
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.json"
            bad.write_text(json.dumps({"unexpected": {"value": "x"}}), encoding="utf-8")
            with self.assertRaises(collector.CollectorError):
                collector.terraform_values(bad)

    def test_application_source_parser_requires_the_exact_separated_source(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
            end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
            document = json.loads((ROOT / "fixtures/d1-native-records.json").read_text(encoding="utf-8"))["was_source_event"]
            when, anchors, _ = collector.app_record(args, "was", [{"message": json.dumps(document)}], start, end)
            self.assertEqual(collector.utc_text(when), "2026-08-13T00:00:01Z")
            self.assertEqual(anchors["query_id"], document["query_id"])
            document["source"] = "web"
            with self.assertRaises(collector.NoNativeMatch):
                collector.app_record(args, "was", [{"message": json.dumps(document)}], start, end)

    def test_nginx_request_tap_ignores_modsecurity_audit_noise_but_rejects_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
            end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
            tap = {"timestamp": "2026-08-13T00:00:01+00:00", "service": "nginx modsecurity", "transaction_id": "nginx-tx-1", "run_id": args.run_id, "request_id": args.request_id}
            events = [{"message": "--abc-A--\nModSecurity: Warning.\n--abc-Z--"}, {"message": json.dumps(tap)}]
            _, anchors, raw = collector.app_record(args, "nginx_modsecurity", events, start, end)
            self.assertEqual(anchors["transaction_id"], "nginx-tx-1")
            self.assertEqual(raw, json.dumps(tap).encode("utf-8"))
            with self.assertRaises(collector.CollectorError):
                collector.app_record(args, "nginx_modsecurity", events + [{"message": json.dumps(tap)}], start, end)

    def test_bounded_poll_retries_only_absent_native_records(self):
        args = arguments(ROOT)
        results = [collector.NoNativeMatch("not delivered"), ("ready",)]
        def probe():
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        with mock.patch.object(collector.time, "sleep") as sleep:
            self.assertEqual(collector.poll(args, probe), ("ready",))
        sleep.assert_called_once_with(1)
        with self.assertRaises(collector.CollectorError):
            collector.select_one(["one", "two"], lambda _: True, "web")

    def test_cloudwatch_pagination_collects_every_page_and_rejects_stuck_token(self):
        args = arguments(ROOT)
        start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
        end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
        pages = [{"events": [{"message": "first"}], "nextToken": "next"}, {"events": [{"message": "second"}]}]
        with mock.patch.object(collector, "run_aws", side_effect=pages) as aws:
            events = collector.cloudwatch_events(args, "/argus/base/web", start, end)
        self.assertEqual([event["message"] for event in events], ["first", "second"])
        self.assertIn("--next-token", aws.call_args_list[1].args[1])
        with mock.patch.object(collector, "run_aws", return_value={"events": [], "nextToken": "same"}):
            with self.assertRaises(collector.CollectorError):
                collector.cloudwatch_events(args, "/argus/base/web", start, end)

    def test_source_failure_leaves_no_runtime_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = arguments(root)
            args.poll_timeout_seconds = 300
            Path(args.redaction_key_file).write_bytes(b"test-key")
            with mock.patch.object(collector, "one_https_request"), mock.patch.object(collector, "alb_record", side_effect=collector.CollectorError("missing ALB record")):
                with self.assertRaises(collector.CollectorError):
                    collector.main(args)
            self.assertFalse((root / args.run_id / "d1-runtime-manifest.json").exists())
            self.assertFalse((root / args.run_id / "collection-audit.json").exists())
            failure = json.loads((root / args.run_id / "collection-failure.json").read_text(encoding="utf-8"))
            self.assertFalse(failure["manifest_written"])

    def test_alb_parser_uses_native_line_and_refuses_duplicate_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
            end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
            line = "https 2026-08-13T00:00:01.000000Z app/alb 8.8.8.8:443 10.0.0.1:8080 0 0 0 200 200 1 2 \"GET https://argus-base.ar0nica.xyz/d1/observe HTTP/1.1\" \"ARGUS\" - - arn:aws:elasticloadbalancing:region:account:targetgroup/x/y " + args.trace_id
            config = {"alb_bucket": "log-bucket", "alb_prefix": "alb/AWSLogs/111/elasticloadbalancing/region/"}
            def aws(_, command):
                if command[0:2] == ["s3api", "list-objects-v2"]:
                    return {"Contents": [{"Key": "alb/AWSLogs/111/elasticloadbalancing/region/2026/08/13/log.gz", "LastModified": "2026-08-13T00:00:02+00:00"}]}
                Path(command[-1]).write_bytes(gzip.compress((line + "\n").encode("utf-8")))
                return {"ContentLength": 1}
            with mock.patch.object(collector, "run_aws", side_effect=aws):
                when, anchors, raw = collector.alb_record(args, config, start, end)
            self.assertEqual(collector.utc_text(when), "2026-08-13T00:00:01Z")
            self.assertEqual(anchors["request_anchor"], "GET https://argus-base.ar0nica.xyz/d1/observe HTTP/1.1")
            self.assertIn(args.trace_id.encode("utf-8"), raw)

    def test_one_https_request_requires_exact_d1_contract_and_trace_header(self):
        class Response:
            status = 200
            headers = Message()
            def __enter__(self): return self
            def __exit__(self, *unused): return False
            def read(self, unused):
                return json.dumps({"fixture_id": "BEN-D1-OBS-001", "run_id": "ARGUS-20260813-BASE-R01", "request_id": "ARGUS-20260813-BASE-R01-BEN-D1-OBS-001", "waf_status": "disabled_not_evaluated", "hybridnb_status": "disabled_not_evaluated", "row_count": 1}).encode("utf-8")
        Response.headers["Content-Type"] = "application/json"
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            with mock.patch.object(collector.urllib.request, "urlopen", return_value=Response()) as opened:
                collector.one_https_request(args)
            request = opened.call_args.args[0]
            self.assertEqual(request.full_url, "https://argus-base.ar0nica.xyz/d1/observe")
            self.assertEqual(request.get_header("X-argus-fixture-id"), "BEN-D1-OBS-001")
            self.assertEqual(request.get_header("X-amzn-trace-id"), args.trace_id)
            args.path = "/health"
            with self.assertRaises(collector.CollectorError):
                collector.main(args)

    def test_native_rds_and_cloudtrail_parsers_use_real_correlation_shapes(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
            end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
            query_id = "123e4567-e89b-42d3-a456-426614174000"
            fixture = json.loads((ROOT / "fixtures/d1-native-records.json").read_text(encoding="utf-8"))
            rds = [{"message": fixture["rds_general_line"]}]
            when, anchors, raw = collector.rds_record(args, rds, start, end, query_id)
            self.assertEqual(collector.utc_text(when), "2026-08-13T00:00:01Z")
            self.assertEqual(anchors, {"connection_id": 42, "query_id": query_id})
            self.assertIn(query_id.encode("utf-8"), raw)
            rds_z = [{"message": fixture["rds_general_line"].replace("2026-08-13 00:00:01", "2026-08-13T00:00:01.123456Z")}]
            when_z, anchors_z, _ = collector.rds_record(args, rds_z, start, end, query_id)
            self.assertEqual(collector.utc_text(when_z), "2026-08-13T00:00:01Z")
            self.assertEqual(when_z.microsecond, 123456)
            self.assertEqual(anchors_z, anchors)
            cloudtrail = [{"message": json.dumps(fixture["cloudtrail_ssm_getparameter"])}]
            _, ct_anchors, _ = collector.cloudtrail_record(args, "cloudtrail", cloudtrail, start, end)
            self.assertEqual(ct_anchors["principal"], "arn:aws:iam::111111111111:role/argus")

    def test_host_parser_selects_atomic_marker_rename_from_native_audit_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            args.host_process = "python"
            start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
            end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
            prefix = "node=i-0123456789abcdef0 type=SYSCALL msg=audit(1786579201.044:"
            suffix = "): pid=3956 comm=\"python\" key=\"argus_d1_observe\" ARCH=x86_64 "
            events = [
                {"message": prefix + "537" + suffix + "SYSCALL=open"},
                {"message": prefix + "538" + suffix + "SYSCALL=rename"},
            ]
            when, anchors, raw = collector.cw_text_record(args, "host", events, start, end)
            self.assertEqual(collector.utc_text(when), "2026-08-13T00:00:01Z")
            self.assertEqual(anchors["audit_serial"], 538)
            self.assertIn(b"SYSCALL=rename", raw)

    def test_flow_parser_selects_only_the_forward_was_to_rds_tuple(self):
        with tempfile.TemporaryDirectory() as directory:
            args = arguments(Path(directory))
            start = collector.parse_utc("2026-08-13T00:00:00Z", "test")
            end = collector.parse_utc("2026-08-13T00:10:00Z", "test")
            prefix = "2 111111111111 eni-0123456789abcdef0 "
            events = [
                {"message": prefix + "10.0.10.10 10.0.20.10 34848 3306 6 20 4118 1786579201 1786579201 ACCEPT OK"},
                {"message": prefix + "10.0.20.10 10.0.10.10 3306 34848 6 20 4118 1786579201 1786579201 ACCEPT OK"},
            ]
            when, anchors, raw = collector.cw_text_record(args, "flow_logs", events, start, end)
            self.assertEqual(collector.utc_text(when), "2026-08-13T00:00:01Z")
            self.assertEqual(anchors["srcaddr"], "10.0.10.10")
            self.assertEqual(anchors["dstaddr"], "10.0.20.10")
            self.assertEqual(anchors["dstport"], 3306)
            self.assertEqual(anchors["protocol"], 6)
            self.assertIn(b"10.0.10.10 10.0.20.10 34848 3306 6", raw)
