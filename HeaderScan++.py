import requests
import json
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

SEC_HEADERS = {
    "Content-Security-Policy": 10,
    "Strict-Transport-Security": 8,
    "X-Frame-Options": 6,
    "X-Content-Type-Options": 4,
    "Referrer-Policy": 3,
    "Permissions-Policy": 2,
    "X-XSS-Protection": 2
}

def classify_severity(score):
    if score >= 30:
        return "Critical"
    elif score >= 20:
        return "High"
    elif score >= 10:
        return "Medium"
    else:
        return "Low"

def scan_url(url, verbose=False):
    headers = {}
    score = 0
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        for header, weight in SEC_HEADERS.items():
            value = response.headers.get(header)
            if value:
                headers[header] = {"status": "Present", "value": value}
            else:
                headers[header] = {"status": "Missing"}
                score += weight
        severity = classify_severity(score)
        result = {
            "url": url,
            "score": score,
            "severity": severity,
            "headers": headers
        }
        if verbose:
            print(f"\n{Fore.CYAN}Scanning: {url}")
            print(f"Score: {Fore.YELLOW}{score} ({severity})")
            for h, val in headers.items():
                if val["status"] == "Missing":
                    print(f"{Fore.RED}- {h}: Missing")
                else:
                    print(f"{Fore.GREEN}+ {h}: {val['value']}")
        return result
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}Error scanning {url}: {e}")
        return {
            "url": url,
            "error": str(e)
        }

def save_json(results, path):
    with open(path, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    print(f"{Fore.GREEN}Saved results to {path}")

def save_csv(results, path):
    with open(path, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        headers = ["URL", "Score", "Severity"] + list(SEC_HEADERS.keys())
        writer.writerow(headers)
        for r in results:
            row = [r.get("url"), r.get("score"), r.get("severity")]
            for h in SEC_HEADERS:
                row.append(r["headers"].get(h, {}).get("status", "Error"))
            writer.writerow(row)
    print(f"{Fore.GREEN}Saved results to {path}")

def load_urls(source):
    try:
        with open(source, "r", encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Failed to read file {source}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="HeaderScan++ - Security Headers Scanner")
    parser.add_argument("target", help="URL or file with list of URLs")
    parser.add_argument("-o", "--output", help="Output file (json or csv)", default=None)
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for batch scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
    args = parser.parse_args()

    urls = [args.target] if args.target.startswith("http") else load_urls(args.target)
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_url, url, args.verbose) for url in urls]
        for f in futures:
            results.append(f.result())

    if args.output:
        if args.output.endswith(".json"):
            save_json(results, args.output)
        elif args.output.endswith(".csv"):
            save_csv(results, args.output)
        else:
            print(f"{Fore.RED}Unsupported output format: {args.output}")
    else:
        print(f"{Fore.YELLOW}No output file specified, results only shown on screen.")

if __name__ == "__main__":
    main()
