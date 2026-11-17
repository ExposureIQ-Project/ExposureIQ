"""Reviewed defensive guidance, not measurements or instructions to an agent.

Effort means a typical planning range, not a promise about this organization.
Commands below are a fixed recheck reminder for an authorized human. Nothing
here executes a command, contacts a target or changes scope.
"""

from __future__ import annotations

import copy

RECHECK = ("After the change, repeat only your usual authorized checks: exposureiq scan <domain> again, then exposureiq diff. "
           "Use the same scope and previously approved opt-in checks; a passive scan alone cannot verify active findings.")
HSTS_NOTE = ('Only after HTTPS works, nginx can use: add_header Strict-Transport-Security "max-age={hsts_max_age}" always; '
             'Apache with mod_headers can use: Header always set Strict-Transport-Security "max-age={hsts_max_age}". '
             'Do not add includeSubDomains or preload until every affected site is ready.')


def _entry(what, why, steps, effort, who, check, *, server_note=""):
    return {"what": what, "why": why, "steps": tuple(steps), "effort": effort, "who": who,
            "verify": check, "recheck": RECHECK, "server_note": server_note}


FIXES = {
    "ports.database_exposed": _entry(
        "A database stores information for an application.",
        "If access controls are weak, public database access could let someone read, change or delete stored data.",
        ("Ask the application owner which systems genuinely need database access.",
         "Have IT block public connections at the firewall and allow only those approved application systems.",
         "Keep the database on a private network and give each application only the permissions it needs.",
         "Check that the application still works before closing the change."),
        "hours; moving an application to a private network can take days", "IT or the database administrator, with the application owner",
        "Confirm that approved applications still connect and that the saved public-port finding is absent after the authorized recheck."),
    "ports.remote_desktop_exposed": _entry(
        "Remote desktop lets someone use a computer from another location.",
        "If sign-in controls fail, public remote desktop could let someone control that computer's desktop.",
        ("Ask IT who needs remote access and keep a safe administrative route open during the change.",
         "Move access behind an approved VPN or remote-access gateway, not a public connection.",
         "Require strong sign-in controls, including an extra sign-in factor where supported.",
         "Limit access to approved staff and check that their remote access still works."),
        "hours; a new access gateway can take days", "IT or the network administrator",
        "Confirm approved staff can still connect through the private route and the public remote-desktop finding is absent."),
    "ports.smb_exposed": _entry(
        "SMB, short for Server Message Block, shares files between computers.",
        "If file permissions are weak, public SMB access could let someone read, change or delete shared files.",
        ("Ask IT which people and computers need the shared folders.",
         "Block SMB from the public internet at the firewall; keep it on approved private networks.",
         "Review shared-folder permissions and remove access that is not needed.",
         "Check that approved staff can still use their folders and that backups are available."),
        "hours; reorganizing shared folders can take days", "IT or the file-server administrator",
        "Confirm private file sharing still works and the public SMB finding is absent after the authorized recheck."),
    "ports.telnet_exposed": _entry(
        "Telnet is an old remote-login service that does not encrypt the connection.",
        "Someone on the connection could read login details or commands because Telnet does not encrypt them.",
        ("Ask the system owner whether anyone still depends on Telnet.",
         "Set up an approved encrypted administrative connection, such as SSH, before removing old access.",
         "Disable Telnet and block its public access at the firewall.",
         "Check that approved administrators can still manage the system through the replacement."),
        "hours; older equipment that needs replacement can take days", "IT or the equipment administrator",
        "Confirm the encrypted replacement works and the Telnet finding is absent after the authorized recheck."),
    "ports.ftp_exposed": _entry(
        "Plain FTP transfers files without encrypting the connection.",
        "Someone on the connection could read file contents or login details if transfers use plain FTP.",
        ("Ask the service owner which file transfers still use FTP.", "Replace those transfers with an approved encrypted file-transfer service.",
         "Restrict access to approved people and systems, then disable plain FTP.", "Check the replacement transfers before closing the change."),
        "hours; updating dependent transfers can take days", "IT or the file-transfer service administrator",
        "Confirm the replacement transfers work and the plain FTP finding is absent."),
    "ports.ssh_exposed": _entry(
        "SSH provides encrypted remote administration.", "Public SSH gives more people a place to try signing in; an open port alone does not show a compromise.",
        ("Ask the system owner which administrators need SSH.", "Limit network access to approved administrators or a private administrative network.",
         "Use managed sign-in keys and disable password login only after confirming key access works.", "Keep a recovery route and verify approved administration still works."),
        "hours", "IT or the system administrator", "Confirm approved key-based access works and unnecessary public SSH access is removed."),
    "ports.admin_interface_exposed": _entry(
        "An administration interface manages a service's settings.", "If sign-in controls fail, public administration access could let someone change the service.",
        ("Ask the service owner who needs administrative access.", "Restrict the interface to approved private networks or an approved access gateway.",
         "Require strong sign-in controls and remove unused administrator accounts.", "Check that approved administrators still have a safe way to manage the service."),
        "hours; setting up a new access gateway can take days", "IT or the service administrator",
        "Confirm approved administration works and the unnecessary public interface is no longer exposed."),
    "https.not_available": _entry(
        "HTTPS encrypts the connection between a visitor and a website.", "Without working HTTPS, website traffic may be readable or changeable on the connection.",
        ("Ask the hosting provider or website administrator to enable HTTPS for this exact website name.",
         "Install a trusted certificate and its complete chain.", "Check the secure site before redirecting plain HTTP to HTTPS.",
         "Set up certificate renewal and alerts so the secure connection stays available."),
        "hours; hosting or name-ownership changes can take days", "the website administrator or hosting provider",
        "Check the exact website name in a clean browser without a certificate warning and repeat the previously authorized HTTPS check."),
    "https.cert_expired": _entry(
        "An expired certificate is a website identity document past its valid period.", "Visitors may see security warnings or be unable to connect; expiry alone does not prove data was stolen.",
        ("Ask the website administrator or hosting provider to renew the certificate for this exact website name.",
         "Deploy the renewed certificate and its complete chain on the system that serves the site.",
         "Check the site from a clean browser and confirm that the warning has gone.", "Enable automatic renewal and an expiry alert."),
        "minutes to hours; ownership or deployment problems can take days", "the website administrator or hosting provider",
        "Confirm the browser accepts the renewed certificate and the expired-certificate finding is absent."),
    "https.cert_expiring_soon": _entry(
        "The website certificate will need renewal soon.", "If renewal is missed, visitors may see warnings or lose access to the secure site.",
        ("Ask the website administrator to schedule renewal before expiry.", "Check that automatic renewal can complete and deploy the certificate.",
         "Confirm the renewed certificate is actually served by the website.", "Keep an expiry alert with a named owner."),
        "minutes to hours", "the website administrator or hosting provider", "Confirm the new validity period and that the expiry-soon finding is absent."),
    "https.cert_hostname_mismatch": _entry(
        "The certificate does not cover the exact website name being used.", "Browsers may warn that the site's identity does not match its name.",
        ("Confirm the website name users should visit.", "Ask the hosting provider to issue or select a trusted certificate covering that exact name.",
         "Deploy it on the system serving the site and check the correct site configuration.", "Check the exact name from a clean browser."),
        "hours; name-ownership changes can take days", "the website administrator or hosting provider", "Confirm the exact website name opens without an identity warning."),
    "https.cert_self_signed": _entry(
        "A self-signed certificate is not automatically trusted by public browsers.", "Public visitors may see an identity warning; that warning alone is not proof of interception.",
        ("Confirm whether this site is intended for public visitors or a managed private environment.", "For a public site, obtain a certificate from a trusted certificate authority.",
         "Deploy the certificate with its complete chain.", "Check it from a clean browser without a custom trust exception."),
        "hours", "the website administrator or hosting provider", "Confirm public browsers trust the certificate without adding an exception."),
    "https.cert_untrusted": _entry(
        "The browser cannot verify the website certificate's trust chain.", "Visitors may see identity warnings or be unable to use the secure site.",
        ("Ask the website administrator to check the issuing authority and intermediate certificates.", "Replace an unsuitable certificate with a trusted certificate for the exact website name.",
         "Deploy the complete certificate chain on the system serving the site.", "Test with a clean browser that has no special trust exceptions."),
        "hours", "the website administrator or hosting provider", "Confirm a clean browser accepts the complete chain without an identity warning."),
    "headers.missing_hsts": _entry(
        "HSTS tells a browser to keep using encrypted website connections.", "Without this browser rule, later visits may still start on a plain connection.",
        ("Confirm HTTPS and the certificate work reliably before changing this rule.", "Ask the website administrator to add Strict-Transport-Security on HTTPS responses.",
         "Use the reviewed duration and test ordinary site visits.", "Extend the rule to other site names only after all those sites are ready."),
        "minutes to hours; making HTTPS reliable can take days", "the website administrator or hosting provider",
        "Confirm HTTPS responses carry the intended Strict-Transport-Security policy and the saved HSTS finding is absent.", server_note=HSTS_NOTE),
    "headers.weak_hsts": _entry(
        "The HSTS browser rule is present but weaker than the reviewed check expects.", "A weak duration can limit how long the browser remembers to use the secure connection.",
        ("Confirm HTTPS and the certificate work reliably.", "Ask the website administrator to strengthen Strict-Transport-Security to the reviewed duration.",
         "Check that the rule appears on the actual HTTPS response.", "Avoid extending it to unprepared site names."),
        "minutes to hours", "the website administrator or hosting provider", "Confirm the intended HSTS duration is served and the weak-HSTS finding is absent.", server_note=HSTS_NOTE),
    "headers.missing_csp": _entry(
        "CSP is a browser policy limiting which scripts and resources a page may use.", "If the site has a content-injection flaw, a suitable policy may reduce what unwanted code can run in visitors' browsers.",
        ("Ask the website administrator which scripts and resources the front page needs.", "Create a policy allowing only those necessary sources.",
         "Test it in report-only mode with ordinary site use before enforcing it.", "Review reports and enforce the tested policy without breaking the page."),
        "hours to days", "the website administrator with the application developer", "Confirm the enforced Content-Security-Policy is present and ordinary page features still work."),
    "headers.weak_csp": _entry(
        "The site's content security policy allows broader script behavior than intended.", "A permissive policy may do less to limit unwanted code if another site flaw exists.",
        ("Ask the application developer which script sources are genuinely needed.", "Review default-src and script-src and narrow broad wildcards.",
         "Replace unsafe-inline and unsafe-eval where the application can support a tested safer policy.", "Test normal site use before enforcing the change."),
        "hours to days", "the website administrator with the application developer", "Confirm the enforced policy passes the saved check and the site's normal features still work."),
    "headers.missing_x_content_type_options": _entry(
        "The content-type rule tells a browser to respect the file type the site declares.", "Without it, a browser may guess a file type differently from the site's intention.",
        ("Ask the website administrator to check that files have the correct Content-Type.", "Add X-Content-Type-Options: nosniff to site responses.",
         "Test normal page loads and downloads before closing the change."),
        "minutes to hours", "the website administrator or hosting provider", "Confirm the response includes X-Content-Type-Options: nosniff and normal downloads work."),
    "headers.missing_clickjacking_protection": _entry(
        "Frame protection limits which other pages can embed this website.", "If a sensitive page is embedded deceptively, a visitor could be tricked into clicking the wrong control.",
        ("Ask the website owner whether any approved pages must embed this site.", "Set CSP frame-ancestors to those approved sources, or an appropriate X-Frame-Options rule.",
         "Test approved embedding and normal page use before enforcing the change."),
        "minutes to hours; approved embedding changes can take days", "the website administrator with the application developer",
        "Confirm the intended frame policy is served and approved embedding still works."),
    "headers.missing_referrer_policy": _entry(
        "A referrer policy limits how much of a page's address is shared with another site.", "Without an appropriate rule, more address information than needed may be sent with outgoing requests.",
        ("Ask the website owner which address information other sites genuinely need.", "Set Referrer-Policy to strict-origin-when-cross-origin or a suitable stricter policy.",
         "Test normal links and any approved features that rely on referrer information."),
        "minutes to hours", "the website administrator or hosting provider", "Confirm the chosen Referrer-Policy is served and normal links still work."),
    "headers.missing_permissions_policy": _entry(
        "A permissions policy limits browser features such as camera or location access.", "Without it, pages may have access to browser features the site does not need, subject to browser permissions.",
        ("Ask the application developer which browser features are actually required.", "Set Permissions-Policy to disable unnecessary features.",
         "Test any approved feature before enforcing the policy."),
        "minutes to hours", "the website administrator with the application developer", "Confirm the intended Permissions-Policy is served and approved features still work."),
    "tech.server_version_disclosed": _entry(
        "The Server response header exposes a software version hint.", "A version hint can help someone narrow down software to investigate; it is not proof of a vulnerability.",
        ("Ask the website administrator which system adds the Server header.", "Reduce the version detail using that system's documented settings where supported.",
         "Keep the server software updated and test normal site responses."),
        "minutes to hours", "the website administrator or hosting provider", "Confirm the exposed version detail is reduced and the site still responds normally."),
    "tech.powered_by_disclosed": _entry(
        "The X-Powered-By response header exposes an application-platform hint.", "That hint may help identify the platform, but it does not establish a known vulnerability.",
        ("Ask the application developer which layer adds X-Powered-By.", "Remove or reduce that header using the platform's documented settings.",
         "Keep the platform updated and test ordinary site use."),
        "minutes to hours", "the application developer or hosting provider", "Confirm the X-Powered-By detail is reduced and normal site features work."),
    "tech.generator_version_disclosed": _entry(
        "An HTML generator tag exposes a site-generator version hint.", "A version hint can help identify software, but it does not prove that the site is vulnerable.",
        ("Ask the website administrator which generator or theme creates the version tag.", "Remove the version detail using the generator's supported setting or template.",
         "Keep the generator updated and check the front page after the change."),
        "minutes to hours", "the website administrator or application developer", "Confirm the generator version is no longer exposed and the front page still works."),
}


def fix_for(rule: str) -> dict:
    """Return a private copy; an unknown saved rule gets no invented advice."""
    return copy.deepcopy(FIXES.get(rule, {}))
