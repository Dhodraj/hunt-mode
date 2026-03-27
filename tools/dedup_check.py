#!/usr/bin/env python3
"""
Dedup checker — search HackerOne Hacktivity for similar disclosed reports.
Run this BEFORE submitting any report to check if it's already known.

Usage:
  python3 tools/dedup_check.py "gitlab ssrf"
  python3 tools/dedup_check.py "gitlab import" --limit 10
  python3 tools/dedup_check.py "keycloak redirect"
"""
import json
import sys
import urllib.request
import urllib.parse
import argparse


def search_hacktivity(query, limit=5):
    """Search HackerOne Hacktivity via the public search API."""
    url = f"https://hackerone.com/hacktivity/overview?queryString={urllib.parse.quote(query)}&sortField=latest_disclosable_activity_at&sortDirection=DESC&pageSize={limit}"

    # Use the REST-like endpoint
    api_url = "https://hackerone.com/graphql"
    graphql_query = """
    query HacktivitySearch($query: String!, $limit: Int!) {
      search(query: $query, first: $limit, type: HACKTIVITY_ITEM) {
        nodes {
          ... on HacktivityItemInterface {
            __typename
            ... on Disclosed {
              report {
                title
                substate
                disclosed_at
                severity_rating
                url
                team {
                  handle
                }
                bounty_amount
              }
            }
            ... on HacktivityItemCommunity {
              report {
                title
                url
              }
            }
          }
        }
      }
    }
    """

    # Simpler approach: use the web scraping-friendly endpoint
    search_url = f"https://hackerone.com/hacktivity?querystring={urllib.parse.quote(query)}"

    print(f"[*] Searching HackerOne Hacktivity for: {query}")
    print(f"[*] Manual check: {search_url}")
    print()

    # Try the API
    try:
        payload = json.dumps({
            "operationName": "HacktivitySearchQuery",
            "variables": {
                "querystring": query,
                "size": limit,
                "from": 0
            },
            "query": """query HacktivitySearchQuery($querystring: String, $size: Int, $from: Int) {
              hacktivity_items(
                querystring: $querystring
                size: $size
                from: $from
                sort_field: latest_disclosable_activity_at
                sort_direction: DESC
                state: DISCLOSED
              ) {
                total_count
                edges {
                  node {
                    ... on Disclosed {
                      id
                      reporter { username }
                      report {
                        title
                        substate
                        url
                        severity_rating
                      }
                      team { handle name }
                      awarded_amount
                      latest_disclosable_activity_at
                    }
                  }
                }
              }
            }"""
        }).encode("utf-8")

        req = urllib.request.Request(
            api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

            if "errors" in data:
                print(f"[!] API returned errors — schema may have changed")
                print(f"[*] Use manual search instead: {search_url}")
                return

            items = data.get("data", {}).get("hacktivity_items", {})
            total = items.get("total_count", 0)
            edges = items.get("edges", [])

            print(f"Found {total} disclosed reports matching '{query}':")
            print()

            for edge in edges:
                node = edge.get("node", {})
                report = node.get("report", {})
                team = node.get("team", {})
                print(f"  [{report.get('severity_rating', '?')}] {report.get('title', 'N/A')}")
                print(f"    Program: {team.get('handle', '?')} | Bounty: ${node.get('awarded_amount', '?')}")
                print(f"    URL: {report.get('url', 'N/A')}")
                print()

    except Exception as e:
        print(f"[!] API search failed: {e}")
        print(f"[*] Use manual search: {search_url}")
        print()
        print("Quick manual check:")
        print(f"  1. Open: {search_url}")
        print(f"  2. Look for reports matching your finding")
        print(f"  3. If similar report exists → likely duplicate")


def main():
    parser = argparse.ArgumentParser(description="Check HackerOne Hacktivity for duplicates")
    parser.add_argument("query", help="Search query (e.g., 'gitlab ssrf', 'shopify idor')")
    parser.add_argument("--limit", type=int, default=5, help="Number of results")
    args = parser.parse_args()

    search_hacktivity(args.query, args.limit)


if __name__ == "__main__":
    main()
