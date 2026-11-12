# /// script
# dependencies = [
#     "cryptography>=42.0.0",
# ]
# ///
"""
Zero-Knowledge Secret Santa Generator (CLI)
Uses Sattolo's algorithm for uniform single-cycle derangements and AES-GCM encryption
to generate tamper-proof, private gift links for GitHub Pages.
"""

import argparse
import base64
import json
import secrets
import sys
from typing import Dict, List, Set, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def parse_exclusions(exclusion_args: List[str]) -> Dict[str, Set[str]]:
    """
    Parses exclusion pairs in the format 'Alice:Bob' (bidirectional) or 'Alice->Bob' (directed).
    """
    exclusions: Dict[str, Set[str]] = {}
    for item in exclusion_args:
        item = item.strip()
        if not item:
            continue
        if "->" in item:
            src, dst = item.split("->", 1)
            src, dst = src.strip(), dst.strip()
            exclusions.setdefault(src, set()).add(dst)
        elif ":" in item:
            p1, p2 = item.split(":", 1)
            p1, p2 = p1.strip(), p2.strip()
            exclusions.setdefault(p1, set()).add(p2)
            exclusions.setdefault(p2, set()).add(p1)
    return exclusions


def generate_cycle(
    names: List[str],
    exclusions: Dict[str, Set[str]],
    max_rejection_attempts: int = 5000,
) -> List[Tuple[str, str]]:
    """
    Generates a single cycle derangement using Sattolo's algorithm with rejection sampling.
    Falls back to randomized backtracking if rejection sampling exceeds max attempts.
    """
    n = len(names)
    if n < 2:
        raise ValueError("Must have at least 2 participants.")

    # 1. Rejection sampling of Sattolo cycle
    for _ in range(max_rejection_attempts):
        pool = names.copy()
        for i in range(n - 1, 0, -1):
            j = secrets.randbelow(i)
            pool[i], pool[j] = pool[j], pool[i]

        valid = True
        pairs = []
        for k in range(n):
            giver = pool[k]
            receiver = pool[(k + 1) % n]
            if giver == receiver or receiver in exclusions.get(giver, set()):
                valid = False
                break
            pairs.append((giver, receiver))
        if valid:
            return pairs

    # 2. Backtracking fallback for heavily constrained exclusion graphs
    import random
    rng = random.SystemRandom()

    def backtrack(current_cycle: List[str], remaining: Set[str]) -> List[str] | None:
        if not remaining:
            # Check closure from last to first
            if current_cycle[0] in exclusions.get(current_cycle[-1], set()) or current_cycle[0] == current_cycle[-1]:
                return None
            return current_cycle

        current_giver = current_cycle[-1]
        candidates = [c for c in remaining if c != current_giver and c not in exclusions.get(current_giver, set())]
        rng.shuffle(candidates)

        for next_person in candidates:
            res = backtrack(current_cycle + [next_person], remaining - {next_person})
            if res is not None:
                return res
        return None

    all_names = list(names)
    rng.shuffle(all_names)
    start_person = all_names[0]
    cycle = backtrack([start_person], set(all_names[1:]))

    if cycle is None:
        raise RuntimeError("No valid Secret Santa cycle exists with the given exclusion constraints.")

    return [(cycle[k], cycle[(k + 1) % n]) for k in range(n)]


def encrypt_payload(data: dict) -> Tuple[str, str]:
    """
    Encrypts a JSON dict using AES-GCM 128-bit.
    Returns:
      payload_b64: base64url(nonce + ciphertext_with_tag)
      key_b64: base64url(key)
    """
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    payload_b64 = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")
    key_b64 = base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")
    return payload_b64, key_b64


def main():
    parser = argparse.ArgumentParser(
        description="Zero-Knowledge Secret Santa Generator for GitHub Pages"
    )
    parser.add_argument(
        "--names",
        type=str,
        help="Comma-separated participant names (e.g. 'Alice,Bob,Charlie')",
    )
    parser.add_argument(
        "--names-file",
        type=str,
        help="Path to text file with names (one per line)",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default="https://alfredbirkelund.github.io/secret-santa",
        help="Base URL of your GitHub Pages site",
    )
    parser.add_argument(
        "--budget",
        type=str,
        default="",
        help="Optional gift budget (e.g. '200 DKK' or '$25')",
    )
    parser.add_argument(
        "--note",
        type=str,
        default="",
        help="Optional event note or date (e.g. 'Exchange Dec 24 at Grandma\\'s')",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclusions like 'Alice:Bob' (bidirectional) or 'Alice->Bob' (can be passed multiple times)",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        help="Optional file path to save the distribution links",
    )

    args = parser.parse_args()

    # Collect names
    names: List[str] = []
    if args.names:
        names = [n.strip() for n in args.names.split(",") if n.strip()]
    elif args.names_file:
        with open(args.names_file, "r", encoding="utf-8") as f:
            names = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        print("🎅 Secret Santa Interactive Setup")
        print("Enter participant names (one per line). Enter empty line to finish:")
        while True:
            try:
                line = input("> ").strip()
                if not line:
                    break
                names.append(line)
            except (EOFError, KeyboardInterrupt):
                print()
                break

    if len(names) < 2:
        print("Error: At least 2 names are required.", file=sys.stderr)
        sys.exit(1)

    exclusions = parse_exclusions(args.exclude)

    base_url = args.base_url.rstrip("/")

    # Generate derangement cycle
    try:
        pairs = generate_cycle(names, exclusions)
    except Exception as e:
        print(f"Error generating pairings: {e}", file=sys.stderr)
        sys.exit(1)

    # Sort pairs alphabetically by giver so the output order gives zero clue about the cycle sequence!
    # If output followed cycle order (A->B, B->C), someone reading the list of givers would know the chain.
    # Sorting by giver name completely scrambles the cycle!
    import random
    giver_records = []
    for giver, receiver in pairs:
        data = {
            "giver": giver,
            "recipient": receiver,
        }
        if args.budget:
            data["budget"] = args.budget
        if args.note:
            data["note"] = args.note

        payload_b64, key_b64 = encrypt_payload(data)
        link = f"{base_url}/#{payload_b64}.{key_b64}"
        giver_records.append((giver, link))

    giver_records.sort(key=lambda x: x[0].lower())

    out_lines = []
    out_lines.append("=" * 68)
    out_lines.append("🎄 SECRET SANTA DISTRIBUTION LINKS (ZERO-KNOWLEDGE)")
    out_lines.append("=" * 68)
    out_lines.append("Send each participant their private link below.")
    out_lines.append("DO NOT OPEN THEM YOURSELF — the recipient is known ONLY to their link!")
    out_lines.append("-" * 68)
    max_len = max(len(g) for g, _ in giver_records)
    for giver, link in giver_records:
        out_lines.append(f"{giver.ljust(max_len)} : {link}")
    out_lines.append("=" * 68)

    full_output = "\n".join(out_lines)
    print("\n" + full_output + "\n")

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(full_output + "\n")
        print(f"✓ Saved distribution links to {args.output_file}")


if __name__ == "__main__":
    main()
