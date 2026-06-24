REMEDIATION_MAP = {
    "Missing Content-Security-Policy": {
        "impact": "Without a Content-Security-Policy, the application is highly vulnerable to Cross-Site Scripting (XSS) attacks. Attackers who find an injection vector can execute arbitrary scripts without browser restrictions.",
        "remediation": "Implement a strict CSP header. Start with `default-src 'self';` and iteratively allow necessary external resources. Avoid using `'unsafe-inline'` or `'unsafe-eval'`."
    },
    "Missing Strict-Transport-Security": {
        "impact": "Failure to enforce HSTS allows attackers to perform Man-in-The-Middle (MitM) attacks by stripping HTTPS connections down to HTTP, potentially exposing session tokens and credentials.",
        "remediation": "Configure the web server to send the `Strict-Transport-Security` header with a high `max-age` (e.g., `max-age=31536000; includeSubDomains; preload`)."
    },
    "Missing X-Frame-Options": {
        "impact": "The application can be embedded in an iframe on a malicious third-party site, leading to Clickjacking attacks where users are tricked into performing unintended actions.",
        "remediation": "Add the `X-Frame-Options` header set to `DENY` or `SAMEORIGIN`. Alternatively, use the `frame-ancestors` directive within your Content-Security-Policy."
    },
    "Missing X-Content-Type-Options": {
        "impact": "Browsers may perform MIME-type sniffing, allowing attackers to upload malicious files (like JS masquerading as images) that the browser will execute.",
        "remediation": "Set the `X-Content-Type-Options` header exactly to `nosniff` on all HTTP responses."
    },
    "Missing Referrer-Policy": {
        "impact": "Sensitive information in the URL (like session tokens or password reset links) may be leaked to third-party sites via the Referer header when users click external links.",
        "remediation": "Set the `Referrer-Policy` header to `strict-origin-when-cross-origin` to prevent leaking full URLs to external domains."
    },
    "Missing Permissions-Policy": {
        "impact": "Third-party scripts or embedded content may access sensitive browser APIs (like camera, microphone, or geolocation) without strict controls.",
        "remediation": "Add a `Permissions-Policy` header explicitly disabling features you do not need, e.g., `camera=(), microphone=(), geolocation=()`."
    },
    "Server Header Disclosure": {
        "impact": "Exposing the exact web server and OS version allows attackers to easily identify known CVEs targeting your infrastructure.",
        "remediation": "Configure your web server to suppress or obfuscate the `Server` header. In Nginx, use `server_tokens off;`."
    },
    "X-Powered-By Disclosure": {
        "impact": "Revealing the backend technology stack (e.g., PHP, Express, ASP.NET) aids attackers in tailoring framework-specific exploits.",
        "remediation": "Remove the `X-Powered-By` header in your application framework configuration."
    },
    "Login Form Detected": {
        "impact": "The presence of a login form over public networks makes it a prime target for brute force, credential stuffing, and phishing if not properly secured.",
        "remediation": "Ensure the login form is protected by strong rate-limiting, CAPTCHA, and MFA. Ensure all form submissions use HTTPS POST."
    },
    "Password Field Detected": {
        "impact": "Password fields indicate authentication mechanisms are present. If autocomplete is not disabled or if the form submits over HTTP, credentials can be intercepted.",
        "remediation": "Verify that password hashing uses strong algorithms (e.g., Argon2), and the connection is strictly TLS-enforced."
    },
    "Password Form over HTTP": {
        "impact": "Submitting passwords over an unencrypted HTTP connection allows any network eavesdropper to capture credentials in plaintext.",
        "remediation": "Redirect all traffic to HTTPS, enforce HSTS, and change the form action URL to strictly use `https://`."
    },
    "Missing Autocomplete Attribute on Password Field": {
        "impact": "Without explicit autocomplete directives, browsers or password managers may improperly autofill credentials, sometimes leading to accidental exposure in cross-site contexts.",
        "remediation": "Add `autocomplete=\"current-password\"` or `autocomplete=\"new-password\"` to the password input field."
    },
    "Cleartext HTTP Usage": {
        "impact": "Traffic is unencrypted, allowing attackers on the same network (e.g., public Wi-Fi) to intercept sensitive data, inject malware, or steal session cookies.",
        "remediation": "Obtain a TLS certificate (e.g., via Let's Encrypt), configure your web server to listen on port 443, and enforce HTTP to HTTPS 301 redirects."
    },
    "Mixed Content": {
        "impact": "Loading insecure HTTP resources (like scripts or images) on a secure HTTPS page completely compromises the integrity of the secure page, allowing MitM script injection.",
        "remediation": "Update all internal links and external asset references (images, scripts, CSS) to use `https://` or protocol-relative URLs (`//`)."
    },
    "Wildcard Access-Control-Allow-Origin": {
        "impact": "Using `*` in the CORS origin header allows any malicious website to read the responses of cross-origin requests made to this endpoint.",
        "remediation": "Configure CORS to only allow specific, trusted origins. Never use `*` on endpoints handling sensitive data."
    },
    "Credentials with permissive origin": {
        "impact": "Allowing credentials (cookies/auth headers) alongside a permissive origin (or dynamically reflected origin) allows complete cross-site data theft by malicious domains.",
        "remediation": "Never combine `Access-Control-Allow-Credentials: true` with a wildcard or poorly validated dynamic origin. Hardcode the allowed origins."
    },
    "robots.txt found": {
        "impact": "While normal, `robots.txt` files often accidentally disclose hidden admin directories, staging environments, or internal API paths to attackers.",
        "remediation": "Review the contents of `robots.txt` to ensure no sensitive or secret paths are listed. Disallow paths only if they are genuinely public but shouldn't be indexed."
    },
    "sitemap.xml found": {
        "impact": "Sitemaps map out the application's entire public surface area, which can accidentally include paths to unlinked or administrative pages.",
        "remediation": "Ensure your sitemap generation script strictly excludes private, administrative, or authenticated paths."
    },
    "security.txt found": {
        "impact": "A `security.txt` file is best practice for bug bounty programs, but if outdated, it can lead researchers to dead endpoints or incorrect reporting structures.",
        "remediation": "Ensure the `security.txt` file is up-to-date, conforms to RFC 9116, and clearly outlines your vulnerability disclosure policy."
    },
    "sensitive-looking public file found": {
        "impact": "Exposing files like `.env`, `.git`, or backup archives leads to complete system compromise via hardcoded secrets, database passwords, or source code leakage.",
        "remediation": "Immediately remove public access to these files. Configure your web server to deny access to dotfiles (`.*`) and move configuration files outside the web root."
    }
}

def get_remediation_for_finding(title: str, default_description: str = "") -> dict:
    """
    Returns a dictionary containing 'impact' and 'remediation'.
    """
    # Exact match
    if title in REMEDIATION_MAP:
        return REMEDIATION_MAP[title]
        
    # Partial match for dynamically generated titles
    for key, data in REMEDIATION_MAP.items():
        if key.lower() in title.lower():
            return data
            
    # Default fallback
    return {
        "impact": "The exact impact depends on the specific context of the vulnerability. Generally, it may lead to information disclosure or unauthorized access.",
        "remediation": "Review the specific finding details and apply security best practices relevant to the affected technology stack."
    }
