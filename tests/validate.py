#!/usr/bin/env python3
"""
Mirqab Cloud Relay - Validation Tests
Validates infrastructure, Kubernetes manifests, and Go code without external dependencies
"""

import os
import sys
import re
import json
import yaml
from pathlib import Path
from typing import List, Tuple, Dict, Any

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def print_header(text: str):
    print(f"\n{Colors.BLUE}{'='*60}{Colors.NC}")
    print(f"{Colors.BLUE}  {text}{Colors.NC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}\n")

def print_section(text: str):
    print(f"\n{Colors.BLUE}--- {text} ---{Colors.NC}\n")

def print_pass(test_name: str):
    print(f"{Colors.GREEN}✓ PASS: {test_name}{Colors.NC}")

def print_fail(test_name: str, reason: str = ""):
    msg = f"{Colors.RED}✗ FAIL: {test_name}{Colors.NC}"
    if reason:
        msg += f" ({reason})"
    print(msg)

def print_skip(test_name: str, reason: str = ""):
    print(f"{Colors.YELLOW}○ SKIP: {test_name}{Colors.NC}" + (f" ({reason})" if reason else ""))

class TestRunner:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.results: List[Dict[str, Any]] = []

    def run_test(self, name: str, test_func, *args, **kwargs) -> bool:
        try:
            result = test_func(*args, **kwargs)
            if result:
                print_pass(name)
                self.passed += 1
                self.results.append({"name": name, "status": "pass"})
                return True
            else:
                print_fail(name)
                self.failed += 1
                self.results.append({"name": name, "status": "fail"})
                return False
        except Exception as e:
            print_fail(name, str(e))
            self.failed += 1
            self.results.append({"name": name, "status": "fail", "error": str(e)})
            return False

    def skip_test(self, name: str, reason: str = ""):
        print_skip(name, reason)
        self.skipped += 1
        self.results.append({"name": name, "status": "skip", "reason": reason})

    def file_exists(self, path: str) -> bool:
        return (self.project_root / path).exists()

    def file_contains(self, path: str, pattern: str) -> bool:
        filepath = self.project_root / path
        if not filepath.exists():
            return False
        content = filepath.read_text()
        return pattern in content or re.search(pattern, content) is not None

    def validate_yaml(self, path: str) -> bool:
        filepath = self.project_root / path
        if not filepath.exists():
            return False
        try:
            content = filepath.read_text()
            list(yaml.safe_load_all(content))
            return True
        except Exception:
            return False

    def validate_go_syntax(self, path: str) -> bool:
        """Basic Go syntax validation - check for balanced braces and required keywords"""
        filepath = self.project_root / path
        if not filepath.exists():
            return False
        content = filepath.read_text()

        # Check for required Go keywords
        required = ['package', 'func', 'import']
        for kw in required:
            if kw not in content:
                return False

        # Check for balanced braces
        if content.count('{') != content.count('}'):
            return False
        if content.count('(') != content.count(')'):
            return False

        return True

    def validate_terraform(self, path: str) -> bool:
        """Basic Terraform validation - check for required blocks"""
        filepath = self.project_root / path
        if not filepath.exists():
            return False
        content = filepath.read_text()

        # Check for terraform block or resource/module definitions
        has_valid_blocks = (
            'terraform {' in content or
            'resource "' in content or
            'variable "' in content or
            'module "' in content
        )

        # Check for balanced braces
        if content.count('{') != content.count('}'):
            return False

        return has_valid_blocks

def main():
    # Get project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    runner = TestRunner(str(project_root))

    print_header("Mirqab Cloud Relay - Validation Suite")

    # ==========================================================================
    # File Structure Tests
    # ==========================================================================
    print_section("Project Structure")

    runner.run_test(
        "Project directory structure exists",
        lambda: all([
            runner.file_exists("terraform/modules/eks"),
            runner.file_exists("terraform/modules/networking"),
            runner.file_exists("kubernetes/base"),
            runner.file_exists("services/c2-http"),
            runner.file_exists("services/c2-dns"),
            runner.file_exists("tests"),
        ])
    )

    runner.run_test(
        "EKS Terraform module exists",
        lambda: runner.file_exists("terraform/modules/eks/main.tf")
    )

    runner.run_test(
        "Networking Terraform module exists",
        lambda: runner.file_exists("terraform/modules/networking/main.tf")
    )

    runner.run_test(
        "C2 HTTP service exists",
        lambda: runner.file_exists("services/c2-http/main.go")
    )

    runner.run_test(
        "C2 DNS service exists",
        lambda: runner.file_exists("services/c2-dns/main.go")
    )

    # ==========================================================================
    # Terraform Validation
    # ==========================================================================
    print_section("Terraform Validation")

    runner.run_test(
        "EKS module syntax valid",
        lambda: runner.validate_terraform("terraform/modules/eks/main.tf")
    )

    runner.run_test(
        "Networking module syntax valid",
        lambda: runner.validate_terraform("terraform/modules/networking/main.tf")
    )

    runner.run_test(
        "EKS module has cluster_name variable",
        lambda: runner.file_contains("terraform/modules/eks/main.tf", 'variable "cluster_name"')
    )

    runner.run_test(
        "EKS module has vpc_id variable",
        lambda: runner.file_contains("terraform/modules/eks/main.tf", 'variable "vpc_id"')
    )

    runner.run_test(
        "EKS module has cluster_endpoint output",
        lambda: runner.file_contains("terraform/modules/eks/main.tf", 'output "cluster_endpoint"')
    )

    runner.run_test(
        "EKS module has OIDC provider output",
        lambda: runner.file_contains("terraform/modules/eks/main.tf", 'output "oidc_provider_arn"')
    )

    runner.run_test(
        "EKS uses KMS encryption for secrets",
        lambda: runner.file_contains("terraform/modules/eks/main.tf", 'aws_kms_key')
    )

    runner.run_test(
        "Networking module has vpc_id output",
        lambda: runner.file_contains("terraform/modules/networking/main.tf", 'output "vpc_id"')
    )

    runner.run_test(
        "Networking module has VPC flow logs",
        lambda: runner.file_contains("terraform/modules/networking/main.tf", 'aws_flow_log')
    )

    # ==========================================================================
    # Kubernetes Manifest Validation
    # ==========================================================================
    print_section("Kubernetes Manifest Validation")

    runner.run_test(
        "Namespace template YAML valid",
        lambda: runner.validate_yaml("kubernetes/base/namespace-template.yaml")
    )

    runner.run_test(
        "Cilium config YAML valid",
        lambda: runner.validate_yaml("kubernetes/base/cilium-config.yaml")
    )

    runner.run_test(
        "gVisor runtime YAML valid",
        lambda: runner.validate_yaml("kubernetes/base/gvisor-runtime.yaml")
    )

    runner.run_test(
        "C2 HTTP deployment YAML valid",
        lambda: runner.validate_yaml("kubernetes/base/c2-http-deployment.yaml")
    )

    runner.run_test(
        "C2 DNS deployment YAML valid",
        lambda: runner.validate_yaml("kubernetes/base/c2-dns-deployment.yaml")
    )

    # ==========================================================================
    # Security Configuration Tests
    # ==========================================================================
    print_section("Security Configuration")

    runner.run_test(
        "Namespace has default-deny NetworkPolicy",
        lambda: runner.file_contains("kubernetes/base/namespace-template.yaml", "default-deny-all")
    )

    runner.run_test(
        "Namespace has ResourceQuota",
        lambda: runner.file_contains("kubernetes/base/namespace-template.yaml", "kind: ResourceQuota")
    )

    runner.run_test(
        "Namespace has LimitRange",
        lambda: runner.file_contains("kubernetes/base/namespace-template.yaml", "kind: LimitRange")
    )

    runner.run_test(
        "Pod Security Standards enforced (restricted)",
        lambda: runner.file_contains("kubernetes/base/namespace-template.yaml", "pod-security.kubernetes.io/enforce: restricted")
    )

    runner.run_test(
        "C2 HTTP uses gVisor runtime",
        lambda: runner.file_contains("kubernetes/base/c2-http-deployment.yaml", "runtimeClassName: gvisor")
    )

    runner.run_test(
        "C2 HTTP runs as non-root",
        lambda: runner.file_contains("kubernetes/base/c2-http-deployment.yaml", "runAsNonRoot: true")
    )

    runner.run_test(
        "C2 HTTP drops all capabilities",
        lambda: runner.file_contains("kubernetes/base/c2-http-deployment.yaml", "drop:") and
                runner.file_contains("kubernetes/base/c2-http-deployment.yaml", "- ALL")
    )

    runner.run_test(
        "C2 HTTP has read-only root filesystem",
        lambda: runner.file_contains("kubernetes/base/c2-http-deployment.yaml", "readOnlyRootFilesystem: true")
    )

    runner.run_test(
        "C2 DNS uses gVisor runtime",
        lambda: runner.file_contains("kubernetes/base/c2-dns-deployment.yaml", "runtimeClassName: gvisor")
    )

    runner.run_test(
        "C2 DNS runs as non-root",
        lambda: runner.file_contains("kubernetes/base/c2-dns-deployment.yaml", "runAsNonRoot: true")
    )

    runner.run_test(
        "Cilium WireGuard encryption enabled",
        lambda: runner.file_contains("kubernetes/base/cilium-config.yaml", 'enable-wireguard: "true"')
    )

    runner.run_test(
        "Cilium policy enforcement always",
        lambda: runner.file_contains("kubernetes/base/cilium-config.yaml", 'policy-enforcement: "always"')
    )

    # ==========================================================================
    # Go Code Validation
    # ==========================================================================
    print_section("Go Code Validation")

    runner.run_test(
        "C2 HTTP main.go syntax valid",
        lambda: runner.validate_go_syntax("services/c2-http/main.go")
    )

    runner.run_test(
        "C2 DNS main.go syntax valid",
        lambda: runner.validate_go_syntax("services/c2-dns/main.go")
    )

    runner.run_test(
        "C2 HTTP has health endpoint",
        lambda: runner.file_contains("services/c2-http/main.go", '/health')
    )

    runner.run_test(
        "C2 HTTP has ready endpoint",
        lambda: runner.file_contains("services/c2-http/main.go", '/ready')
    )

    runner.run_test(
        "C2 HTTP has Prometheus metrics",
        lambda: runner.file_contains("services/c2-http/main.go", 'prometheus.MustRegister')
    )

    runner.run_test(
        "C2 HTTP has beacon endpoints",
        lambda: runner.file_contains("services/c2-http/main.go", '/api/v1/update') and
                runner.file_contains("services/c2-http/main.go", '/api/v1/telemetry')
    )

    runner.run_test(
        "C2 HTTP has session management",
        lambda: runner.file_contains("services/c2-http/main.go", 'SessionManager') and
                runner.file_contains("services/c2-http/main.go", 'BeaconSession')
    )

    runner.run_test(
        "C2 HTTP has jitter implementation",
        lambda: runner.file_contains("services/c2-http/main.go", 'JitterPercent') and
                runner.file_contains("services/c2-http/main.go", 'calculateBeaconInterval')
    )

    runner.run_test(
        "C2 HTTP has TLS support",
        lambda: runner.file_contains("services/c2-http/main.go", 'TLSEnabled') and
                runner.file_contains("services/c2-http/main.go", 'ListenAndServeTLS')
    )

    runner.run_test(
        "C2 HTTP has admin authentication",
        lambda: runner.file_contains("services/c2-http/main.go", 'adminAuthMiddleware') and
                runner.file_contains("services/c2-http/main.go", 'X-Admin-Token')
    )

    runner.run_test(
        "C2 DNS has health endpoint",
        lambda: runner.file_contains("services/c2-dns/main.go", '/health')
    )

    runner.run_test(
        "C2 DNS has Prometheus metrics",
        lambda: runner.file_contains("services/c2-dns/main.go", 'prometheus.MustRegister')
    )

    runner.run_test(
        "C2 DNS supports A records",
        lambda: runner.file_contains("services/c2-dns/main.go", 'handleARecord') and
                runner.file_contains("services/c2-dns/main.go", 'dns.TypeA')
    )

    runner.run_test(
        "C2 DNS supports TXT records",
        lambda: runner.file_contains("services/c2-dns/main.go", 'handleTXTRecord') and
                runner.file_contains("services/c2-dns/main.go", 'dns.TypeTXT')
    )

    runner.run_test(
        "C2 DNS supports AAAA records",
        lambda: runner.file_contains("services/c2-dns/main.go", 'handleAAAARecord') and
                runner.file_contains("services/c2-dns/main.go", 'dns.TypeAAAA')
    )

    runner.run_test(
        "C2 DNS has base32 encoding for DNS-safe data",
        lambda: runner.file_contains("services/c2-dns/main.go", 'base32')
    )

    # ==========================================================================
    # Dockerfile Validation
    # ==========================================================================
    print_section("Dockerfile Validation")

    runner.run_test(
        "C2 HTTP Dockerfile exists",
        lambda: runner.file_exists("services/c2-http/Dockerfile")
    )

    runner.run_test(
        "C2 HTTP uses multi-stage build",
        lambda: runner.file_contains("services/c2-http/Dockerfile", "AS builder")
    )

    runner.run_test(
        "C2 HTTP uses distroless base",
        lambda: runner.file_contains("services/c2-http/Dockerfile", "distroless")
    )

    runner.run_test(
        "C2 HTTP runs as non-root user",
        lambda: runner.file_contains("services/c2-http/Dockerfile", "USER 65534")
    )

    runner.run_test(
        "C2 DNS Dockerfile exists",
        lambda: runner.file_exists("services/c2-dns/Dockerfile")
    )

    runner.run_test(
        "C2 DNS uses multi-stage build",
        lambda: runner.file_contains("services/c2-dns/Dockerfile", "AS builder")
    )

    runner.run_test(
        "C2 DNS uses distroless base",
        lambda: runner.file_contains("services/c2-dns/Dockerfile", "distroless")
    )

    # ==========================================================================
    # Unit Test Files
    # ==========================================================================
    print_section("Test Coverage")

    runner.run_test(
        "C2 HTTP unit tests exist",
        lambda: runner.file_exists("tests/unit/c2_http_test.go")
    )

    runner.run_test(
        "C2 DNS unit tests exist",
        lambda: runner.file_exists("tests/unit/c2_dns_test.go")
    )

    runner.run_test(
        "HTTP tests cover session creation",
        lambda: runner.file_contains("tests/unit/c2_http_test.go", "TestNewSessionCreation")
    )

    runner.run_test(
        "HTTP tests cover session persistence",
        lambda: runner.file_contains("tests/unit/c2_http_test.go", "TestSessionPersistence")
    )

    runner.run_test(
        "HTTP tests cover beacon interval jitter",
        lambda: runner.file_contains("tests/unit/c2_http_test.go", "TestBeaconIntervalJitter")
    )

    runner.run_test(
        "DNS tests cover A record exfiltration",
        lambda: runner.file_contains("tests/unit/c2_dns_test.go", "TestARecordDataExfiltration")
    )

    runner.run_test(
        "DNS tests cover TXT command retrieval",
        lambda: runner.file_contains("tests/unit/c2_dns_test.go", "TestTXTRecordCommandRetrieval")
    )

    # ==========================================================================
    # Summary
    # ==========================================================================
    print_header("Test Results Summary")

    total = runner.passed + runner.failed + runner.skipped
    print(f"Total Tests:  {total}")
    print(f"{Colors.GREEN}Passed:       {runner.passed}{Colors.NC}")
    print(f"{Colors.RED}Failed:       {runner.failed}{Colors.NC}")
    print(f"{Colors.YELLOW}Skipped:      {runner.skipped}{Colors.NC}")
    print()

    # Calculate pass rate
    if total > 0:
        pass_rate = (runner.passed / total) * 100
        print(f"Pass Rate:    {pass_rate:.1f}%")
        print()

    if runner.failed == 0:
        print(f"{Colors.GREEN}All tests passed!{Colors.NC}")
        return 0
    else:
        print(f"{Colors.RED}Some tests failed. Please review the output above.{Colors.NC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
