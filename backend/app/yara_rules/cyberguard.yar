/*
    CYBERGUARD starter YARA rules — ATTACH-SCAN Phase 2.

    Design policy: conservative by intent. Every rule either anchors on a
    file-format magic (so text/HTML noise cannot trigger format rules) or
    requires long, specific phrases that essentially never occur in benign
    documents. Starter rules favour false-negative over false-positive:
    a missed obfuscation is worse to lose than a rule, but analysts stop
    trusting a scanner that cries wolf.
*/

rule CyberGuard_MacroAutoOpen : office macro
{
    meta:
        description = "Office document containing auto-executing VBA macro hooks (AutoOpen/AutoExec/Document_Open)"
        severity = "medium"
    strings:
        $auto_open  = "AutoOpen" ascii wide
        $auto_exec  = "AutoExec" ascii wide
        $doc_open   = "Document_Open" ascii wide
        $doc_close  = "Document_Close" ascii wide
    condition:
        // OLE2 compound file magic only (legacy .doc/.xls/.ppt) — keeps the
        // rule quiet on zip-based OOXML where VBA is compressed anyway.
        uint32be(0) == 0xD0CF11E0 and 1 of ($auto_*, $doc_*)
}

rule CyberGuard_PDF_JavaScript : pdf javascript
{
    meta:
        description = "PDF embedding JavaScript or auto-open actions (/JavaScript, /OpenAction)"
        severity = "high"
    strings:
        $pdf_magic   = "%PDF-"
        $js_full     = "/JavaScript" nocase
        $js_short    = /\/JS[\s\(]/ nocase
        $open_action = "/OpenAction" nocase
    condition:
        $pdf_magic at 0 and any of ($js_full, $js_short, $open_action)
}

rule CyberGuard_PDF_EmbeddedFile : pdf embeddedfile
{
    meta:
        description = "PDF carrying embedded file objects (/EmbeddedFile) — common dropper pattern"
        severity = "medium"
    strings:
        $pdf_magic  = "%PDF-"
        $embedded   = "/EmbeddedFile" nocase
    condition:
        $pdf_magic at 0 and $embedded
}

rule CyberGuard_PE_Executable : executable pe
{
    meta:
        description = "Windows PE executable (MZ header plus PE signature)"
        severity = "info"
    strings:
        $pe_sig = { 50 45 00 00 }
    condition:
        uint16(0) == 0x5A4D and $pe_sig
}

rule CyberGuard_Suspicious_URL_Patterns : phishing
{
    meta:
        description = "Known phishing lure phrasing typical of credential-harvest links in text/HTML bodies"
        severity = "medium"
    strings:
        $lure1 = "verify-your-account" nocase ascii
        $lure2 = "confirm-your-identity" nocase ascii
        $lure3 = "update-your-billing" nocase ascii
        $lure4 = "suspicious-login-attempt" nocase ascii
        $lure5 = "secure-login-verification" nocase ascii
        $lure6 = "unlock-your-account-now" nocase ascii
    condition:
        any of them
}

rule CyberGuard_Obfuscated_Strings : obfuscation
{
    meta:
        description = "Obfuscated payload execution patterns (PowerShell -EncodedCommand, eval(atob()), document.write(unescape()))"
        severity = "high"
    strings:
        $ps_enc   = "-EncodedCommand" nocase ascii
        $ps_enc2  = " -enc " nocase ascii
        $atob     = "eval(atob(" nocase ascii
        $unesc    = "document.write(unescape(" nocase ascii
        $chr_buld = "String.fromCharCode(" nocase ascii
    condition:
        1 of ($ps_*) or 1 of ($atob, $unesc) or (2 of ($chr_buld, $atob, $unesc))
}
