"""Reviewed plain-English explanations, not model-created security advice.

These describe the SAME rules and fixes as fingerprint/severity.py. They do
not change saved severity, scan facts or the durable findings format.
"""

SEVERITY_EXPLANATION = (
    "Severity is a fix-priority label. In ExposureIQ, high means direct exposure or unusable HTTPS; "
    "medium means weaker protections or exposed administration; low means smaller hardening gaps. "
    "None of these labels proves a break-in."
)
RISK_EXPLANATION = "The exposure score measures what the scan recorded, not how likely a break-in is. Missing checks can make it look lower."
HEADERS_EXPLANATION = "Security headers are instructions a website sends to browsers to help protect visitors."
COVERAGE_EXPLANATION = "This scan can only tell us what was saved. A missing or failed check does not mean that part is safe."
CONFIRM_EXPLANATION = "After a fix, ask your team to confirm it through the usual authorized checks. I can't run those checks for you."
IMPACT_EXPLANATION = (
    "Here's what could go wrong with the issues in this scan. These are possible consequences, "
    "not evidence that someone broke in or that data was lost."
)
EMPTY_IMPACT_EXPLANATION = (
    "I don't have saved findings to connect to a possible consequence. "
    "Missing checks still aren't proof that everything is safe."
)
IMPACT_LIMITATION = (
    "The scan doesn't tell us what data is stored, how well accounts are protected "
    "or whether anyone used these exposures."
)
INCIDENT_EXPLANATION = (
    "This saved scan can't tell us whether someone broke in. It records exposure, "
    "not account activity or who accessed your data."
)

VERDICT_EXPLANATIONS = {
    "improving": "The saved comparisons point toward less exposure, but they don't prove that every problem is fixed.",
    "worse": "The saved comparisons point toward more exposure. Review the new or returned findings with your team.",
    "stable": "The saved comparisons show no meaningful overall change. That doesn't mean there are no problems to fix.",
    "mixed": "Some saved indicators improved and others worsened, so there isn't one clear direction.",
    "not_enough_data": "There isn't enough comparable saved check data to judge a trend yet.",
}

# rule -> (what it means, defensive next step). No commands or live assertions.
RULE_HELP = {
    "headers.missing_hsts": (
        "HSTS is a browser instruction to keep using encrypted HTTPS connections.",
        "First confirm HTTPS works, then enable the HSTS browser policy with a max-age of at least {hsts_max_age} seconds.",
    ),
    "headers.weak_hsts": (
        "HSTS tells browsers to keep using encrypted HTTPS connections; its saved policy needs strengthening.",
        "First confirm HTTPS works, then strengthen the HSTS policy with a max-age of at least {hsts_max_age} seconds.",
    ),
    "headers.missing_csp": (
        "A content security policy tells browsers which scripts and resources the site allows.",
        "Ask the site owner to add a content security policy that allows only the scripts and resources the site needs.",
    ),
    "headers.weak_csp": (
        "A content security policy tells browsers which scripts and resources the site allows; broad permissions weaken it.",
        "Ask the site owner to tighten the content security policy, limiting script sources and removing unsafe or overly broad permissions.",
    ),
    "headers.missing_x_content_type_options": (
        "Browsers need an instruction to respect the file type the site declares instead of guessing it.",
        "Ask the site owner to send X-Content-Type-Options: nosniff, so browsers respect the declared file type.",
    ),
    "headers.missing_clickjacking_protection": (
        "Frame protection helps stop another site from putting this page inside a misleading embedded frame.",
        "Ask the site owner to set CSP frame-ancestors or X-Frame-Options to block unwanted embedding of the site.",
    ),
    "headers.missing_referrer_policy": (
        "A referrer policy limits the page-address information browsers share when visitors follow a link.",
        "Ask the site owner to use a Referrer-Policy of strict-origin-when-cross-origin or a stricter setting suited to the site.",
    ),
    "headers.missing_permissions_policy": (
        "A permissions policy limits browser features the site doesn't need.",
        "Ask the site owner to add a Permissions-Policy that disables browser features the site doesn't need.",
    ),
    "tech.server_version_disclosed": (
        "A visible software version is an information hint, not proof that the software is vulnerable.",
        "Hide the server version in the Server header and keep the server software updated.",
    ),
    "tech.powered_by_disclosed": (
        "A visible application version is an information hint, not proof that the application is vulnerable.",
        "Remove or reduce the X-Powered-By header and keep the application platform updated.",
    ),
    "tech.generator_version_disclosed": (
        "A visible site-generator version is an information hint, not proof that the site is vulnerable.",
        "Hide the generator version in the page's metadata and keep the site software updated.",
    ),
    "https.not_available": (
        "HTTPS encrypts the connection between a visitor and a website.",
        "Enable HTTPS with a trusted certificate, then redirect unencrypted HTTP connections to HTTPS.",
    ),
    "https.cert_expired": (
        "A certificate is the website's digital identity; an expired one can stop browsers from trusting the connection.",
        "Renew and install the HTTPS certificate, then monitor automatic renewal so it doesn't expire again unnoticed.",
    ),
    "https.cert_expiring_soon": (
        "A certificate is the website's digital identity; renewing it before expiry helps avoid connection warnings.",
        "Renew the HTTPS certificate before it expires and check that automatic renewal works.",
    ),
    "https.cert_hostname_mismatch": (
        "The certificate needs to identify the exact website name that visitors use.",
        "Install a trusted certificate that includes this exact hostname in its allowed names.",
    ),
    "https.cert_self_signed": (
        "Public browsers normally need a certificate issued by an authority they trust, rather than one the site signs itself.",
        "Use a certificate from a trusted certificate authority for the public website.",
    ),
    "https.cert_untrusted": (
        "Browsers need to verify the website's certificate and the chain linking it to a trusted issuer.",
        "Install a trusted certificate with its complete certificate chain, then have your team verify it from a clean client.",
    ),
    "ports.database_exposed": (
        "A database service should normally be reachable only by the applications that need it, not the whole internet.",
        "Move database access behind a private network and allow only approved application hosts to connect.",
    ),
    "ports.remote_desktop_exposed": (
        "Remote desktop gives access to a computer's desktop and should not be open to everyone online.",
        "Limit remote desktop to an approved private network or VPN, a protected connection, and require strong authentication.",
    ),
    "ports.telnet_exposed": (
        "Telnet is an older remote-administration service that doesn't encrypt its connection.",
        "Disable Telnet and use SSH, an encrypted remote-administration service, instead.",
    ),
    "ports.ftp_exposed": (
        "Plain FTP transfers files without encrypting the connection.",
        "Replace plain FTP with encrypted file transfer and restrict who can connect.",
    ),
    "ports.smb_exposed": (
        "SMB is a file-sharing service intended for controlled networks, not unrestricted public access.",
        "Block public access to SMB file-sharing ports and allow it only on approved private networks.",
    ),
    "ports.ssh_exposed": (
        "SSH is an encrypted remote-administration service; access still needs to be limited to approved administrators.",
        "Allow SSH only from approved administrators, use key-based authentication and disable password login.",
    ),
    "ports.admin_interface_exposed": (
        "An administration page or service needs tighter access controls than a public website.",
        "Limit administration interfaces to approved networks and require strong authentication.",
    ),
}

# Possible consequences, conditional on the recorded rule, not observed damage.
# These must not imply that a port, version or missing header proves a breach.
RULE_IMPACT = {
    "headers.missing_hsts": (
        "Without this browser protection, a visitor may start with an unencrypted connection. "
        "Someone on that connection's network could interfere with it before HTTPS is used."
    ),
    "headers.weak_hsts": (
        "A weak policy may leave gaps in the browser's protection against unencrypted connections. "
        "That can make interference on an untrusted network easier."
    ),
    "headers.missing_csp": (
        "If the site also has a flaw that lets unwanted code run in visitors' browsers, the missing "
        "policy removes a layer that could limit it. This finding alone doesn't show that such a flaw exists."
    ),
    "headers.weak_csp": (
        "If harmful scripts get into the site, broad browser permissions may let them do more. "
        "The weak policy alone doesn't prove the site allows unwanted code into its pages."
    ),
    "headers.missing_x_content_type_options": (
        "A browser may guess a file's type incorrectly. In some situations, that could make it "
        "treat untrusted content as something it can run rather than a harmless file."
    ),
    "headers.missing_clickjacking_protection": (
        "Another site may be able to embed this page and mislead visitors into clicking its controls. "
        "Whether a sensitive action is possible depends on what the page allows."
    ),
    "headers.missing_referrer_policy": (
        "When visitors follow links, browsers may share more of the page address than intended. "
        "That could reveal private information if it is included in the address."
    ),
    "headers.missing_permissions_policy": (
        "The site has no explicit policy limiting unused browser features. This leaves one less "
        "restriction on what page content can request; normal browser permissions still apply."
    ),
    "tech.server_version_disclosed": (
        "The version hint can help someone narrow down which known software weaknesses to look for. "
        "It doesn't show that this server has any of those weaknesses."
    ),
    "tech.powered_by_disclosed": (
        "The platform hint can help someone narrow down which known software weaknesses to look for. "
        "It doesn't show that this application has any of those weaknesses."
    ),
    "tech.generator_version_disclosed": (
        "The generator hint can help someone narrow down which known software weaknesses to look for. "
        "It doesn't show that this site has any of those weaknesses."
    ),
    "https.not_available": (
        "If visitors use unencrypted HTTP, someone on their network could read or change the traffic. "
        "Sensitive information would be at risk if it were sent that way."
    ),
    "https.cert_expired": (
        "Visitors may see security warnings or be unable to connect. That can interrupt access and "
        "hurt trust in the site; an expired certificate alone doesn't mean data was stolen."
    ),
    "https.cert_expiring_soon": (
        "If renewal is missed, visitors may get security warnings or lose access when the certificate "
        "expires. The saved finding doesn't say it has expired already."
    ),
    "https.cert_hostname_mismatch": (
        "Browsers may warn that the certificate identifies a different site and block the connection. "
        "That can interrupt access, but doesn't by itself prove someone is impersonating the site."
    ),
    "https.cert_self_signed": (
        "Public browsers may warn or refuse to connect because they cannot establish trust in the "
        "site's identity. A self-signed certificate alone doesn't prove a break-in."
    ),
    "https.cert_untrusted": (
        "Browsers may warn or refuse to connect because they cannot verify the site's identity. "
        "That can disrupt access; it doesn't by itself prove that traffic was intercepted."
    ),
    "ports.database_exposed": (
        "If access controls are weak, someone could read, change or delete stored data. "
        "That could expose private information or interrupt services that depend on the database."
    ),
    "ports.remote_desktop_exposed": (
        "If someone gets past the access controls, they could control the computer's desktop, "
        "reach its files or interrupt work. A reachable remote desktop port alone doesn't show that happened."
    ),
    "ports.telnet_exposed": (
        "If Telnet is used without separate network protection, someone able to observe its traffic "
        "could read login details or commands. That could put the account and system at risk."
    ),
    "ports.ftp_exposed": (
        "If plain FTP is used, someone able to observe the connection could read transferred files "
        "or login details. The open port alone doesn't show which files exist or whether they were accessed."
    ),
    "ports.smb_exposed": (
        "If file-sharing permissions or other protections are weak, someone could reach, change or "
        "delete shared files. That could expose information or disrupt the people using those files."
    ),
    "ports.ssh_exposed": (
        "If an administrator account is compromised, someone could use remote access to reach files "
        "or change the system. SSH encrypts its connection; an open port doesn't prove an account is vulnerable."
    ),
    "ports.admin_interface_exposed": (
        "If the access controls fail, someone could change settings or reach information through the "
        "administration interface. That could affect the service or its users."
    ),
}
