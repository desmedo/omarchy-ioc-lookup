// IOC Classification, Batch Extraction, Defanging/Refanging & History Engine for Omarchy

.pragma library

function cleanInput(raw) {
  if (!raw) return ""
  var s = String(raw).trim()
  // If multi-line, check if it's a single input or a block
  if (s.indexOf("\n") !== -1) {
    var lines = s.split("\n")
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i].trim()
      if (l && l.length > 0) {
        s = l
        break
      }
    }
  }
  // Remove markdown quotes, code blocks, backticks, angle brackets, commas, semicolons at edges
  s = s.replace(/^[`"'\[\(<]+|[`"'\]\)>]+$/g, "")
  s = s.replace(/^src=["']|["']$/g, "")
  s = s.replace(/[,;]+$/, "")
  return s.trim()
}

function refang(raw) {
  if (!raw) return ""
  var s = String(raw).trim()
  // Protocols
  s = s.replace(/h[xX]{2}ps:\/\//gi, "https://")
  s = s.replace(/h[xX]{2}p:\/\//gi, "http://")
  s = s.replace(/f[xX]{2}p:\/\//gi, "ftp://")
  // Dot replacements: [.], (.), {.}, [dot], (dot), {dot}, \.
  s = s.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|\\\./gi, ".")
  // Colon replacements: [:], (:), {:}, [colon]
  s = s.replace(/\[\:\]|\(\:\)|\{\:\}|\[colon\]/gi, ":")
  // At sign replacements: [@], (@), {@}, [at]
  s = s.replace(/\[\@\]|\(\@\)|\{\@\}|\[at\]/gi, "@")
  // Slash replacements: [/], (/), [slash]
  s = s.replace(/\[\/\]|\(\/\)|\[slash\]/gi, "/")
  return s.trim()
}

function defang(raw) {
  if (!raw) return ""
  var s = refang(raw)
  // Protocols
  s = s.replace(/https:\/\//gi, "hxxps://")
  s = s.replace(/http:\/\//gi, "hxxp://")
  s = s.replace(/ftp:\/\//gi, "fxxp://")
  // Dot replacements
  s = s.replace(/\./g, "[.]")
  // At sign replacements
  s = s.replace(/@/g, "[@]")
  return s
}

function isIPv4(val) {
  var parts = val.split(".")
  if (parts.length !== 4) return false
  for (var i = 0; i < 4; i++) {
    var p = parts[i]
    if (!/^\d{1,3}$/.test(p)) return false
    var n = parseInt(p, 10)
    if (n < 0 || n > 255) return false
    if (p.length > 1 && p.charAt(0) === '0') return false
  }
  return true
}

function isIPv6(val) {
  if (!val || val.indexOf(":") === -1) return false
  var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/
  return ipv6Regex.test(val)
}

function isDomain(val) {
  if (!val || val.indexOf(".") === -1 || val.indexOf("/") !== -1 || val.indexOf(":") !== -1) return false
  if (val.length > 253) return false
  var domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/i
  return domainRegex.test(val)
}

function isURL(val) {
  if (!val) return false
  if (/^(https?|ftp|file):\/\//i.test(val)) return true
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\/[^\s]*$/i.test(val)) return true
  return false
}

function isMD5(val) {
  return /^[a-fA-F0-9]{32}$/.test(val)
}

function isSHA1(val) {
  return /^[a-fA-F0-9]{40}$/.test(val)
}

function isSHA256(val) {
  return /^[a-fA-F0-9]{64}$/.test(val)
}

function isSHA512(val) {
  return /^[a-fA-F0-9]{128}$/.test(val)
}

function isCVE(val) {
  return /^CVE-\d{4}-\d{4,7}$/i.test(val)
}

function isASN(val) {
  return /^AS\d{1,10}$/i.test(val)
}

function isBTC(val) {
  return /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/.test(val)
}

function isETH(val) {
  return /^0x[a-fA-F0-9]{40}$/.test(val)
}

function isEmail(val) {
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$/.test(val)
}

function classify(raw) {
  var cleaned = cleanInput(raw)
  if (!cleaned) return { type: "empty", value: "", refanged: "", defanged: "", label: "Empty", icon: "", color: "#94a3b8" }
  
  var ref = refang(cleaned)
  var def = defang(cleaned)

  if (isIPv4(ref)) {
    return { type: "ipv4", value: cleaned, refanged: ref, defanged: def, label: "IPv4 Address", icon: "󰒃", color: "#38bdf8" }
  }
  if (isIPv6(ref)) {
    return { type: "ipv6", value: cleaned, refanged: ref, defanged: def, label: "IPv6 Address", icon: "󰒃", color: "#38bdf8" }
  }
  if (isCVE(ref)) {
    var cveUpper = ref.toUpperCase()
    return { type: "cve", value: cleaned, refanged: cveUpper, defanged: cveUpper, label: "CVE Vulnerability", icon: "", color: "#f87171" }
  }
  if (isSHA256(ref)) {
    return { type: "sha256", value: cleaned, refanged: ref.toLowerCase(), defanged: ref.toLowerCase(), label: "SHA-256 Hash", icon: "󰈚", color: "#a855f7" }
  }
  if (isMD5(ref)) {
    return { type: "md5", value: cleaned, refanged: ref.toLowerCase(), defanged: ref.toLowerCase(), label: "MD5 Hash", icon: "󰈚", color: "#c084fc" }
  }
  if (isSHA1(ref)) {
    return { type: "sha1", value: cleaned, refanged: ref.toLowerCase(), defanged: ref.toLowerCase(), label: "SHA-1 Hash", icon: "󰈚", color: "#c084fc" }
  }
  if (isSHA512(ref)) {
    return { type: "sha512", value: cleaned, refanged: ref.toLowerCase(), defanged: ref.toLowerCase(), label: "SHA-512 Hash", icon: "󰈚", color: "#a855f7" }
  }
  if (isURL(ref)) {
    return { type: "url", value: cleaned, refanged: ref, defanged: def, label: "URL", icon: "", color: "#34d399" }
  }
  if (isDomain(ref)) {
    return { type: "domain", value: cleaned, refanged: ref.toLowerCase(), defanged: def.toLowerCase(), label: "Domain / Hostname", icon: "󰖟", color: "#2dd4bf" }
  }
  if (isEmail(ref)) {
    return { type: "email", value: cleaned, refanged: ref.toLowerCase(), defanged: def.toLowerCase(), label: "Email Address", icon: "󰇮", color: "#60a5fa" }
  }
  if (isASN(ref)) {
    var asnUpper = ref.toUpperCase()
    return { type: "asn", value: cleaned, refanged: asnUpper, defanged: asnUpper, label: "Autonomous System", icon: "󱚟", color: "#fbbf24" }
  }
  if (isBTC(ref)) {
    return { type: "btc", value: cleaned, refanged: ref, defanged: ref, label: "Bitcoin Address", icon: "󰠠", color: "#fb923c" }
  }
  if (isETH(ref)) {
    return { type: "eth", value: cleaned, refanged: ref, defanged: ref, label: "Ethereum Address", icon: "󰠠", color: "#fb923c" }
  }

  return { type: "text", value: cleaned, refanged: ref, defanged: def, label: "String / Query", icon: "", color: "#94a3b8" }
}

// ------------------------------------------------------------- Batch Extractor
function extractAll(rawText) {
  if (!rawText) return []
  var text = String(rawText)
  var seen = {}
  var results = []

  function addMatch(candidate) {
    if (!candidate) return
    var item = classify(candidate)
    if (item.type !== "empty" && item.type !== "text") {
      var key = item.type + ":" + item.refanged
      if (!seen[key]) {
        seen[key] = true
        results.push(item)
      }
    }
  }

  // 1. URLs
  var urlMatches = text.match(/(?:https?|hxxps?|ftp|fxxp|hxxp):\/\/[^\s<>"'`\(\)\[\]]+/gi) || []
  for (var u = 0; u < urlMatches.length; u++) addMatch(urlMatches[u])

  // 2. CVEs
  var cveMatches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []
  for (var c = 0; c < cveMatches.length; c++) addMatch(cveMatches[c])

  // 3. Hashes
  var hash256Matches = text.match(/\b[a-fA-F0-9]{64}\b/g) || []
  for (var h = 0; h < hash256Matches.length; h++) addMatch(hash256Matches[h])

  var hash1Matches = text.match(/\b[a-fA-F0-9]{40}\b/g) || []
  for (var h1 = 0; h1 < hash1Matches.length; h1++) addMatch(hash1Matches[h1])

  var hashMd5Matches = text.match(/\b[a-fA-F0-9]{32}\b/g) || []
  for (var hm = 0; hm < hashMd5Matches.length; hm++) addMatch(hashMd5Matches[hm])

  // 4. IPv4 addresses (including defanged like 1[.]1[.]1[.]1)
  var ipMatches = text.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.\[\]\(\)]{1,3}){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g) || []
  for (var i = 0; i < ipMatches.length; i++) addMatch(ipMatches[i])

  // 5. ASNs
  var asnMatches = text.match(/\bAS\d{1,10}\b/gi) || []
  for (var a = 0; a < asnMatches.length; a++) addMatch(asnMatches[a])

  // 6. Domains (e.g. evil[.]com or evil.com)
  var domainMatches = text.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?[.\[\]\(\)]{1,3})+[a-zA-Z]{2,63}\b/g) || []
  for (var d = 0; d < domainMatches.length; d++) {
    var rawDom = domainMatches[d]
    // Skip if it looks like a filename with code extensions or already caught
    if (!/\.(?:png|jpg|jpeg|gif|svg|webp|qml|js|json|toml|lua|conf|txt|log|py|sh|c|h|cpp|go|rs|css|html|md)$/i.test(refang(rawDom))) {
      addMatch(rawDom)
    }
  }

  return results
}

function getPortals(type, refanged) {
  if (!refanged || type === "empty") return []
  var val = encodeURIComponent(refanged)
  var rawVal = refanged

  if (type === "ipv4" || type === "ipv6") {
    return [
      { id: "vt", name: "VirusTotal", icon: "󰒃", key: "1", url: "https://www.virustotal.com/gui/ip-address/" + val },
      { id: "abuseipdb", name: "AbuseIPDB", icon: "󱚟", key: "2", url: "https://www.abuseipdb.com/check/" + val },
      { id: "shodan", name: "Shodan", icon: "󱂛", key: "3", url: "https://www.shodan.io/host/" + val },
      { id: "otx", name: "AlienVault OTX", icon: "", key: "4", url: "https://otx.alienvault.com/indicator/ip/" + val },
      { id: "greynoise", name: "GreyNoise", icon: "󰇧", key: "5", url: "https://viz.greynoise.io/ip/" + val },
      { id: "talos", name: "Cisco Talos", icon: "󰈚", key: "6", url: "https://talosintelligence.com/reputation_center/lookup?search=" + val },
      { id: "ipinfo", name: "IPinfo.io", icon: "󰖟", key: "7", url: "https://ipinfo.io/" + val }
    ]
  }

  if (type === "domain") {
    return [
      { id: "vt", name: "VirusTotal", icon: "󰒃", key: "1", url: "https://www.virustotal.com/gui/domain/" + val },
      { id: "urlscan", name: "URLScan.io", icon: "󰖟", key: "2", url: "https://urlscan.io/domain/" + val },
      { id: "otx", name: "AlienVault OTX", icon: "", key: "3", url: "https://otx.alienvault.com/indicator/domain/" + val },
      { id: "whois", name: "Whois", icon: "󰈚", key: "4", url: "https://www.whois.com/whois/" + val },
      { id: "securitytrails", name: "SecurityTrails", icon: "󱂛", key: "5", url: "https://securitytrails.com/domain/" + val + "/dns" },
      { id: "mxtoolbox", name: "MXToolbox", icon: "󰇮", key: "6", url: "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + val }
    ]
  }

  if (type === "url") {
    return [
      { id: "vt", name: "VirusTotal", icon: "󰒃", key: "1", url: "https://www.virustotal.com/gui/search/" + val },
      { id: "urlscan", name: "URLScan.io", icon: "󰖟", key: "2", url: "https://urlscan.io/search/#" + val },
      { id: "otx", name: "AlienVault OTX", icon: "", key: "3", url: "https://otx.alienvault.com/indicator/url/" + val },
      { id: "threatfox", name: "ThreatFox", icon: "󱚟", key: "4", url: "https://threatfox.abuse.ch/browse.php?search=" + val }
    ]
  }

  if (type === "md5" || type === "sha1" || type === "sha256" || type === "sha512") {
    return [
      { id: "vt", name: "VirusTotal", icon: "󰒃", key: "1", url: "https://www.virustotal.com/gui/file/" + val },
      { id: "bazaar", name: "MalwareBazaar", icon: "󱚟", key: "2", url: "https://bazaar.abuse.ch/browse.php?search=" + val },
      { id: "ha", name: "Hybrid Analysis", icon: "󰈚", key: "3", url: "https://www.hybrid-analysis.com/search?query=" + val },
      { id: "anyrun", name: "Any.Run", icon: "󰖟", key: "4", url: "https://app.any.run/submissions/#" + val },
      { id: "otx", name: "AlienVault OTX", icon: "", key: "5", url: "https://otx.alienvault.com/indicator/file/" + val }
    ]
  }

  if (type === "cve") {
    var cveId = rawVal.toUpperCase()
    return [
      { id: "nvd", name: "NVD (NIST)", icon: "󰈚", key: "1", url: "https://nvd.nist.gov/vuln/detail/" + cveId },
      { id: "mitre", name: "MITRE CVE", icon: "", key: "2", url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cveId },
      { id: "vulncheck", name: "VulnCheck", icon: "󱂛", key: "3", url: "https://vulncheck.com/cve/" + cveId },
      { id: "exploitdb", name: "Exploit-DB", icon: "󰖟", key: "4", url: "https://www.exploit-db.com/search?cve=" + cveId.replace(/^CVE-/i, "") }
    ]
  }

  if (type === "asn") {
    var asnNum = rawVal.replace(/^AS/i, "")
    return [
      { id: "bgpview", name: "BGPView", icon: "󱚟", key: "1", url: "https://bgpview.io/asn/" + asnNum },
      { id: "peeringdb", name: "PeeringDB", icon: "󰖟", key: "2", url: "https://www.peeringdb.com/asn/" + asnNum },
      { id: "he", name: "Hurricane Electric BGP", icon: "󱂛", key: "3", url: "https://bgp.he.net/AS" + asnNum }
    ]
  }

  if (type === "btc") {
    return [
      { id: "blockchain", name: "Blockchain.com", icon: "󰠠", key: "1", url: "https://www.blockchain.com/explorer/addresses/btc/" + val },
      { id: "blockstream", name: "Blockstream", icon: "󰖟", key: "2", url: "https://blockstream.info/address/" + val }
    ]
  }

  if (type === "eth") {
    return [
      { id: "etherscan", name: "Etherscan", icon: "󰠠", key: "1", url: "https://etherscan.io/address/" + val }
    ]
  }

  // Fallback
  return [
    { id: "vt", name: "VirusTotal Search", icon: "󰒃", key: "1", url: "https://www.virustotal.com/gui/search/" + val },
    { id: "google", name: "Google Threat Search", icon: "", key: "2", url: "https://www.google.com/search?q=" + val }
  ]
}

// ------------------------------------------------------------- Markdown Report Exporter
function generateMarkdownReport(historyList) {
  if (!historyList || historyList.length === 0) return "# IOC Investigation Report\n\nNo indicators investigated yet.\n"
  
  var now = new Date().toISOString().replace("T", " ").substring(0, 19)
  var md = "# IOC Investigation Report\n"
  md += "**Generated:** " + now + "  \n"
  md += "**Total Indicators:** " + historyList.length + "\n\n"
  md += "| Type | Indicator (Refanged) | Indicator (Defanged) | Details / Intelligence |\n"
  md += "|:---|:---|:---|:---|\n"

  for (var i = 0; i < historyList.length; i++) {
    var item = historyList[i]
    var t = item.type || "Indicator"
    var ref = item.refanged || item.query || ""
    var def = item.defanged || defang(ref)
    var sum = (item.summary || "").replace(/\|/g, "\\|").replace(/\n/g, " ")
    md += "| " + t + " | `" + ref + "` | `" + def + "` | " + sum + " |\n"
  }

  md += "\n---\n*Report generated via Omarchy IOCs Lookup Tool*\n"
  return md
}
