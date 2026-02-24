"""Python-native subdomain enumeration."""

from __future__ import annotations

import asyncio
import json
import random
import ssl
from pathlib import Path

import dns.resolver
import httpx

from bbai.tools.wrappers.base import PythonToolWrapper, ToolResult


class PythonSubdomainEnum(PythonToolWrapper):
    """Pure Python subdomain enumeration using DNS brute force and OSINT."""

    # Common subdomains for brute force
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "admin", "portal", "api",
        "test", "dev", "staging", "prod", "production", "beta", "alpha",
        "app", "mobile", "blog", "shop", "store", "support", "help",
        "docs", "documentation", "wiki", "download", "downloads",
        "media", "cdn", "static", "assets", "images", "img",
        "secure", "vpn", "remote", "ssh", "webmail", "email",
        "mx", "ns", "ns1", "ns2", "dns", "dns1", "dns2",
        "server", "server1", "server2", "host", "host1", "host2",
        "backup", "backups", "db", "database", "sql", "mysql", "postgres",
        "redis", "mongo", "elasticsearch", "kibana", "grafana",
        "jenkins", "gitlab", "github", "bitbucket", "svn", "git",
        "cPanel", "whm", "webmin", "phpmyadmin", "pma",
        "cp", "controlpanel", "panel", "manage", "manager",
        "status", "monitor", "monitoring", "stats", "analytics",
        "search", "s", "m", "wap", "sms", "chat", "im",
        "video", "videos", "tv", "stream", "streaming", "live",
        "owa", "autodiscover", "autoconfig", "smtp", "pop", "imap",
        "exchange", "ex", "ex01", "ex02", "lync", "lyncdiscover",
        "sip", "sipexternal", "meet", "dialin", "skype",
        "sharepoint", "sp", "teams", "office", "onedrive",
        "ad", "adfs", "ldap", "dc", "dc1", "dc2", "domain",
        "enterprise", "corporate", "corp", "internal", "intranet",
        "private", "restricted", "auth", "sso", "login", "signin",
        "register", "signup", "account", "accounts", "user", "users",
        "member", "members", "customer", "customers", "client", "clients",
        "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
        "affiliate", "affiliates", "reseller", "resellers",
        "careers", "jobs", "job", "apply", "hr", "humanresources",
        "news", "press", "media", "pressroom", "about", "aboutus",
        "contact", "contactus", "contacts", "feedback", "suggestions",
        "legal", "privacy", "terms", "policy", "policies", "security",
        "trust", "compliance", "gdpr", "cookie", "cookies",
        "sitemap", "sitemap.xml", "robots.txt",
        "old", "new", "v1", "v2", "v3", "api-v1", "api-v2",
        "legacy", "deprecated", "archive", "archives", "history",
        "demo", "sandbox", "playground", "testbed", "lab", "labs",
        "experiment", "experiments", "poc", "proof", "prototype",
        "try", "trial", "preview", "pre", "next", "future",
        "edge", "beta-api", "staging-api", "dev-api", "test-api",
        "stage", "uat", "qa", "qc", "integration", "develop",
        "development", "feature", "features", "branch", "branches",
        "build", "builds", "ci", "cd", "pipeline", "pipelines",
        "artifact", "artifacts", "package", "packages", "registry",
        "npm", "maven", "pypi", "docker", "container", "containers",
        "kube", "kubernetes", "k8s", "helm", "rancher", "openshift",
        "swarm", "nomad", "consul", "vault", "terraform", "tf",
        "ansible", "puppet", "chef", "salt", "vagrant",
        "prometheus", "alertmanager", "thanos", "cortex", "loki",
        "jaeger", "zipkin", "otel", "opentelemetry",
        "argocd", "argo", "flux", "spinnaker", "tekton",
        "istio", "linkerd", "traefik", "nginx", "haproxy",
        "envoy", "consul-connect", "cilium", "calico", "flannel",
        "weave", "metallb", "external-dns", "cert-manager",
        "oauth", "oidc", "saml", "jwt", "auth0", "keycloak",
        "okta", "onelogin", "ping", "duo", "mfa", "2fa",
        "webhook", "webhooks", "callback", "callbacks", "hook", "hooks",
        "event", "events", "eventbus", "message", "messages", "queue", "queues",
        "pubsub", "pub-sub", "topic", "topics", "stream", "streams",
        "ws", "websocket", "websockets", "socket", "sockets", "io",
        "realtime", "real-time", "live", "push", "notification", "notifications",
        "alert", "alerts", "alarm", "alarms", "incident", "incidents",
        "ticket", "tickets", "issue", "issues", "bug", "bugs",
        "feature-request", "feature-requests", "enhancement", "enhancements",
        "feedback", "reviews", "rating", "ratings", "survey", "surveys",
        "poll", "polls", "vote", "votes", "voting", "election", "elections",
        "forum", "forums", "board", "boards", "community", "communities",
        "discussion", "discussions", "thread", "threads", "post", "posts",
        "comment", "comments", "reply", "replies", "reaction", "reactions",
        "like", "likes", "share", "shares", "follow", "follows", "subscribe",
        "subscription", "subscriptions", "membership", "memberships",
        "premium", "pro", "plus", "gold", "silver", "bronze", "vip",
        "exclusive", "special", "limited", "early-access", "waitlist",
        "invite", "invites", "invitation", "invitations", "referral",
        "partner", "affiliate", "sponsor", "sponsors", "advertiser",
        "ad", "ads", "advertising", "marketing", "promo", "promotion",
        "campaign", "campaigns", "newsletter", "mailing", "email", "emails",
        "smtp", "pop3", "imap", "mx", "mx1", "mx2", "mail1", "mail2",
        "exchange", "ex", "outlook", "o365", "office365", "google", "gmail",
        "sendgrid", "mailgun", "mailchimp", "constantcontact", "ses",
        "sftp", "ftps", "rsync", "scp", "tftp", "nfs", "samba", "smb",
        "cifs", "afp", "ftp", "file", "files", "upload", "uploads",
        "download", "downloads", "transfer", "transfers", "sync", "syncs",
        "backup", "backups", "snapshot", "snapshots", "restore", "restores",
        "replica", "replicas", "replication", "mirror", "mirrors",
        "cache", "caches", "caching", "redis", "memcached", "varnish",
        "squid", "nginx-cache", "cloudflare", "fastly", "akamai",
        "cdn", "edge", "edge1", "edge2", "origin", "origin1", "origin2",
        "source", "sources", "upstream", "downstream", "peer", "peers",
        "node", "nodes", "worker", "workers", "slave", "slaves",
        "master", "masters", "primary", "primaries", "secondary",
        "replica", "replicas", "follower", "followers", "leader", "leaders",
        "coordinator", "coordinators", "scheduler", "schedulers",
        "executor", "executors", "runner", "runners", "agent", "agents",
        "bot", "bots", "crawler", "crawlers", "spider", "spiders",
        "scraper", "scrapers", "parser", "parsers", "extractor", "extractors",
        "indexer", "indexers", "search", "searcher", "searchers", "finder",
        "discovery", "discoverer", "scanner", "scanners", "probe", "probes",
        "recon", "reconnaissance", "enum", "enumerator", "enumerators",
        "resolver", "resolvers", "dns", "dns1", "dns2", "ns", "ns1", "ns2",
        "whois", "rdap", "ip", "ipv4", "ipv6", "geo", "geolocation",
        "location", "locations", "region", "regions", "zone", "zones",
        "datacenter", "datacenters", "dc", "dc1", "dc2", "colo", "colocation",
        "cloud", "aws", "amazon", "azure", "microsoft", "gcp", "googlecloud",
        "digitalocean", "do", "linode", "vultr", "ovh", "hetzner", "alibaba",
        "aliyun", "tencent", "tencentcloud", "baidu", "huawei", "huaweicloud",
        "ibm", "ibmcloud", "oracle", "oraclecloud", "salesforce", "heroku",
        "netlify", "vercel", "cloudflare", "fastly", "firebase", "appengine",
        "lambda", "functions", "serverless", "faas", "paas", "iaas", "saas",
    ]

    def __init__(self):
        """Initialize with DNS resolver."""
        super().__init__()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    @property
    def name(self) -> str:
        return "python_subdomain_enum"

    @property
    def category(self) -> str:
        return "subdomain_enum"

    @property
    def description(self) -> str:
        return "Pure Python subdomain enumeration via DNS brute force and certificate transparency"

    async def run(self, target: str, options: dict | None = None) -> ToolResult:
        """Enumerate subdomains."""
        import time
        
        start_time = time.time()
        options = options or {}
        
        # Normalize target
        target = target.replace("https://", "").replace("http://", "").strip("/")
        
        findings = []
        found_subdomains = set()

        # Method 1: Certificate Transparency (crt.sh)
        try:
            ct_results = await self._query_crtsh(target)
            for sub in ct_results:
                if sub not in found_subdomains:
                    found_subdomains.add(sub)
                    findings.append({
                        "type": "subdomain",
                        "host": sub,
                        "source": "crt.sh",
                        "method": "certificate_transparency"
                    })
        except Exception as e:
            pass  # Continue with other methods

        # Method 2: DNS Brute Force (limited set for speed)
        brute_list = options.get("wordlist", self.COMMON_SUBDOMAINS[:100])
        concurrency = options.get("concurrency", 50)
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check_subdomain(sub: str) -> str | None:
            async with semaphore:
                subdomain = f"{sub}.{target}"
                try:
                    await asyncio.to_thread(self.resolver.resolve, subdomain, "A")
                    return subdomain
                except Exception:
                    return None

        # Run brute force
        tasks = [check_subdomain(sub) for sub in brute_list]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result and result not in found_subdomains:
                found_subdomains.add(result)
                findings.append({
                    "type": "subdomain",
                    "host": result,
                    "source": "dns_bruteforce",
                    "method": "dns_resolution"
                })

        execution_time = time.time() - start_time

        return ToolResult(
            success=True,
            tool_name=self.name,
            target=target,
            findings=findings,
            execution_time=execution_time
        )

    async def _query_crtsh(self, domain: str) -> set[str]:
        """Query crt.sh for certificate transparency logs."""
        subdomains = set()
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Split by newlines (some entries have multiple domains)
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            # Remove wildcard prefix
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and sub != domain:
                                subdomains.add(sub)
        
        return subdomains
