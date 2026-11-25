#!/usr/bin/env python3
"""
main.py - TokenSpy: JWT Security Analyzer
CLI entry point: ASCII banner, menu-driven interface, and argparse
commands for non-interactive / scriptable use.

Ethical use notice:
    TokenSpy is built for analyzing JWTs and lab infrastructure you own
    or are explicitly authorized to test. The 'alg:none' endpoint test
    (Feature 4) only runs against a --endpoint you configure yourself;
    it never has a default target. Never use this tool against systems
    you do not own or do not have written authorization to test.
"""

import argparse
import sys

from decoder import decode_jwt, load_token_from_file, load_tokens_from_file, MalformedTokenError
from algorithm_check import check_algorithm, inspect_kid
from signature import verify_signature
from vulnerability_tests import test_alg_none, test_weak_secrets
from claims_analyzer import analyze_claims
from report_generator import (
    build_report,
    render_text_report_colored,
    render_text_report,
    save_text_report,
    save_json_report,
    build_batch_summary_table,
)
from utils import Colors, pretty_json, colorize_severity

VERSION = "1.0.0"

BANNER = rf"""
{Colors.CYAN}{Colors.BOLD}
 _______    _              _____
|__   __|  | |            / ____|
   | | ___ | | _____ _ __| (___  _ __  _   _
   | |/ _ \| |/ / _ \ '_ \\___ \| '_ \| | | |
   | | (_) |   <  __/ | | |____) | |_) | |_| |
   |_|\___/|_|\_\___|_| |_|_____/| .__/ \__, |
                                  | |     __/ |
                                  |_|    |___/
{Colors.RESET}{Colors.BOLD}   TOKENSPY — JWT SECURITY ANALYZER  (v{VERSION}){Colors.RESET}
{Colors.DIM}   Decode • Verify • Attack-test (lab-only) • Report{Colors.RESET}
"""


def _get_token_text(args) -> str:
    if args.token:
        return args.token
    if args.file:
        return load_token_from_file(args.file)
    raise MalformedTokenError("No token provided. Use --token or --file.")


def analyze_one(token_text: str, args, label: str = None) -> dict:
    """Run the full pipeline on one token and return the report dict."""
    decoded = decode_jwt(token_text)

    print(f"\n{Colors.BOLD}-- Header --{Colors.RESET}")
    print(pretty_json(decoded.header))
    print(f"\n{Colors.BOLD}-- Payload --{Colors.RESET}")
    print(pretty_json(decoded.payload))

    alg_result = check_algorithm(decoded.header)
    print(f"\n{Colors.BOLD}-- Algorithm --{Colors.RESET}  {colorize_severity(alg_result['severity'])}  {alg_result['message']}")

    kid_result = inspect_kid(decoded.header.get("kid"))

    signature_result = None
    if args.secret and alg_result.get("hmac_verifiable"):
        signature_result = verify_signature(decoded.signing_input, decoded.signature_b64, args.secret, alg_result["alg"])
        tag = Colors.GREEN + "VALID" + Colors.RESET if signature_result["valid"] else Colors.RED + "INVALID" + Colors.RESET
        print(f"\n{Colors.BOLD}-- Signature --{Colors.RESET}  {tag}  {signature_result['message']}")
    elif args.secret and not alg_result.get("hmac_verifiable"):
        print(f"\n{Colors.BOLD}-- Signature --{Colors.RESET}  Skipped: alg '{alg_result['alg']}' is not an HMAC algorithm TokenSpy can verify.")

    alg_none_result = None
    if args.test_alg_none:
        alg_none_result = test_alg_none(decoded, args.endpoint)
        print(f"\n{Colors.BOLD}-- alg:none Endpoint Test --{Colors.RESET}  {alg_none_result['message']}")

    weak_secret_result = None
    if args.wordlist:
        weak_secret_result = test_weak_secrets(decoded.signing_input, decoded.signature_b64, alg_result.get("alg"), args.wordlist)
        print(f"\n{Colors.BOLD}-- Weak Secret Test --{Colors.RESET}  {weak_secret_result['message']}")

    claims_findings = analyze_claims(decoded.payload)
    print(f"\n{Colors.BOLD}-- Claims Analysis --{Colors.RESET}")
    for f in claims_findings:
        print(f"  [{colorize_severity(f['severity'])}] {f['claim']}: {f['detail']}")

    report = build_report(
        token_source=label or (args.file if args.file else "command-line argument"),
        decoded_token=decoded,
        alg_result=alg_result,
        kid_result=kid_result,
        signature_result=signature_result,
        alg_none_result=alg_none_result,
        weak_secret_result=weak_secret_result,
        claims_findings=claims_findings,
    )

    print(f"\n{Colors.BOLD}OVERALL ASSESSMENT: {colorize_severity(report['overall_assessment'])}{Colors.RESET}")
    return report


def cmd_analyze(args):
    try:
        token_text = _get_token_text(args)
    except MalformedTokenError as exc:
        print(f"{Colors.RED}Error: {exc}{Colors.RESET}")
        sys.exit(1)

    try:
        report = analyze_one(token_text, args, label=args.file or "cli")
    except MalformedTokenError as exc:
        print(f"{Colors.RED}Malformed token: {exc}{Colors.RESET}")
        sys.exit(1)

    if args.report_name:
        save_text_report(report, f"{args.report_name}.txt")
        save_json_report(report, f"{args.report_name}.json")
        print(f"\nReports saved: {args.report_name}.txt, {args.report_name}.json")


def cmd_batch(args):
    try:
        tokens = load_tokens_from_file(args.batch)
    except MalformedTokenError as exc:
        print(f"{Colors.RED}Error: {exc}{Colors.RESET}")
        sys.exit(1)

    reports = []
    for i, token_text in enumerate(tokens, start=1):
        print(f"\n{Colors.MAGENTA}{'#'*70}\n# Token {i}/{len(tokens)}\n{'#'*70}{Colors.RESET}")
        try:
            report = analyze_one(token_text, args, label=f"{args.batch}#{i}")
            reports.append(report)
        except MalformedTokenError as exc:
            print(f"{Colors.RED}  Skipped (malformed): {exc}{Colors.RESET}")

    print(f"\n{Colors.BOLD}-- Batch Summary --{Colors.RESET}")
    print(build_batch_summary_table(reports))

    if args.report_name:
        for i, report in enumerate(reports, start=1):
            save_text_report(report, f"{args.report_name}_{i}.txt")
            save_json_report(report, f"{args.report_name}_{i}.json")
        print(f"\nPer-token reports saved as {args.report_name}_<n>.txt/.json")


def interactive_menu():
    print(BANNER)
    state = {"token_text": None, "decoded": None, "secret": None}

    while True:
        print(f"""
{Colors.BOLD}[1]{Colors.RESET} Decode JWT
{Colors.BOLD}[2]{Colors.RESET} Analyze JWT Security (full pipeline)
{Colors.BOLD}[3]{Colors.RESET} Verify Signature
{Colors.BOLD}[4]{Colors.RESET} Test Algorithm None (lab endpoint)
{Colors.BOLD}[5]{Colors.RESET} Detect Weak Secrets (wordlist)
{Colors.BOLD}[6]{Colors.RESET} Analyze Claims
{Colors.BOLD}[7]{Colors.RESET} Generate Security Report (full pipeline + save)
{Colors.BOLD}[8]{Colors.RESET} Exit
""")
        choice = input("Select an option [1-8]: ").strip()

        if choice == "8":
            print("Goodbye.")
            break

        if choice == "1":
            token_text = input("Paste JWT: ").strip()
            try:
                decoded = decode_jwt(token_text)
                state["token_text"], state["decoded"] = token_text, decoded
                print(pretty_json({"header": decoded.header, "payload": decoded.payload}))
            except MalformedTokenError as exc:
                print(f"{Colors.RED}Error: {exc}{Colors.RESET}")

        elif choice in ("2", "7"):
            token_text = input("Paste JWT (or press Enter to reuse the last one): ").strip()
            token_text = token_text or state.get("token_text")
            if not token_text:
                print(f"{Colors.RED}No token available.{Colors.RESET}")
                continue
            secret = input("Secret for signature verification (blank to skip): ").strip() or None
            endpoint = input("Lab endpoint URL for alg:none test (blank to skip): ").strip() or None
            wordlist = input("Wordlist path for weak-secret test (blank to skip): ").strip() or None

            class Args:
                pass
            args = Args()
            args.secret, args.endpoint, args.wordlist = secret, endpoint, wordlist
            args.test_alg_none = bool(endpoint)
            args.file = None

            try:
                report = analyze_one(token_text, args, label="interactive")
                if choice == "7":
                    name = input("Report filename (without extension) [tokenspy_report]: ").strip() or "tokenspy_report"
                    save_text_report(report, f"reports/{name}.txt")
                    save_json_report(report, f"reports/{name}.json")
                    print(f"Saved reports/{name}.txt and reports/{name}.json")
            except MalformedTokenError as exc:
                print(f"{Colors.RED}Error: {exc}{Colors.RESET}")

        elif choice == "3":
            if not state.get("decoded"):
                print(f"{Colors.RED}Decode a token first (option 1).{Colors.RESET}")
                continue
            secret = input("Secret: ").strip()
            alg_result = check_algorithm(state["decoded"].header)
            if not alg_result.get("hmac_verifiable"):
                print(f"{Colors.YELLOW}alg '{alg_result['alg']}' is not HMAC-verifiable by TokenSpy.{Colors.RESET}")
                continue
            result = verify_signature(state["decoded"].signing_input, state["decoded"].signature_b64, secret, alg_result["alg"])
            tag = Colors.GREEN + "VALID" if result["valid"] else Colors.RED + "INVALID"
            print(f"{tag}{Colors.RESET} — {result['message']}")

        elif choice == "4":
            if not state.get("decoded"):
                print(f"{Colors.RED}Decode a token first (option 1).{Colors.RESET}")
                continue
            endpoint = input("Your own lab verification endpoint URL: ").strip()
            result = test_alg_none(state["decoded"], endpoint)
            print(result["message"])

        elif choice == "5":
            if not state.get("decoded"):
                print(f"{Colors.RED}Decode a token first (option 1).{Colors.RESET}")
                continue
            wordlist = input("Wordlist file path [wordlists/weak_secrets.txt]: ").strip() or "wordlists/weak_secrets.txt"
            alg_result = check_algorithm(state["decoded"].header)
            result = test_weak_secrets(state["decoded"].signing_input, state["decoded"].signature_b64, alg_result.get("alg"), wordlist)
            print(result["message"])

        elif choice == "6":
            if not state.get("decoded"):
                print(f"{Colors.RED}Decode a token first (option 1).{Colors.RESET}")
                continue
            for f in analyze_claims(state["decoded"].payload):
                print(f"  [{colorize_severity(f['severity'])}] {f['claim']}: {f['detail']}")

        else:
            print(f"{Colors.YELLOW}Invalid choice.{Colors.RESET}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="tokenspy",
        description="TokenSpy — JWT Security Analyzer (lab/educational use only).",
    )
    parser.add_argument("--version", action="version", version=f"TokenSpy {VERSION}")

    sub = parser.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--secret", help="Secret for HMAC signature verification.")
    common.add_argument("--test-alg-none", action="store_true", help="Run the alg:none test against --endpoint.")
    common.add_argument("--endpoint", help="Your own lab verification endpoint URL (required for --test-alg-none).")
    common.add_argument("--wordlist", help="Path to a weak-secret wordlist file.")
    common.add_argument("--report-name", help="Base filename (no extension) to save .txt and .json reports.")

    p_analyze = sub.add_parser("analyze", parents=[common], help="Analyze a single JWT.")
    group = p_analyze.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="JWT string.")
    group.add_argument("--file", help="Path to a file containing one JWT.")

    p_batch = sub.add_parser("batch", parents=[common], help="Analyze several JWTs from a file (one per line).")
    p_batch.add_argument("--batch", required=True, help="Path to a file with one JWT per line.")
    p_batch.add_argument("--token", help=argparse.SUPPRESS, default=None)
    p_batch.add_argument("--file", help=argparse.SUPPRESS, default=None)

    sub.add_parser("menu", help="Launch the interactive menu-driven interface.")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        print(BANNER)
        cmd_analyze(args)
    elif args.command == "batch":
        print(BANNER)
        cmd_batch(args)
    elif args.command == "menu" or args.command is None:
        interactive_menu()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
