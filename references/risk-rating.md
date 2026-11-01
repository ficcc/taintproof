# Risk Rating

Severity is calculated from the OWASP Risk Rating Methodology. Scoring every factor keeps tiers consistent between reviews and shows the reader why a finding landed where it did.

## 1. Score the factors (0 to 9)

Pick the option nearest to what the code and assumptions support.

When another confirmed finding in this report gives the attacker this finding's prerequisite, score as if that prerequisite is already met, and name the finding that provides it. Attackers chain flaws, and scoring each in isolation understates the risk. For example, weak password hashing is scored as if the hashes are readable when a SQL injection in the same report exposes them.

**Threat agent**

| Factor | Options |
| --- | --- |
| Skill level | none 1, some 3, advanced user 5, network and programming 6, penetration testing 9 |
| Motive | low or none 1, possible reward 4, high reward 9 |
| Opportunity | full access or expensive resources 0, special 4, some 7, none needed 9 |
| Size | developers 2, sysadmins 2, intranet users 4, partners 5, authenticated users 6, anonymous internet users 9 |

**Vulnerability**

| Factor | Options |
| --- | --- |
| Ease of discovery | practically impossible 1, difficult 3, easy 7, automated tools 9 |
| Ease of exploit | theoretical 1, difficult 3, easy 5, automated tools 9 |
| Awareness | unknown 1, hidden 4, obvious 6, public knowledge 9 |
| Intrusion detection | active detection 1, logged and reviewed 3, logged without review 8, not logged 9 |

**Technical impact**

| Factor | Options |
| --- | --- |
| Confidentiality | minimal non-sensitive 2, minimal critical or extensive non-sensitive 6, extensive critical 7, all data 9 |
| Integrity | minimal slight 1, minimal serious 3, extensive slight 5, extensive serious 7, all data 9 |
| Availability | minimal secondary 1, minimal primary or extensive secondary 5, extensive primary 7, all services 9 |
| Accountability | fully traceable 1, possibly traceable 7, anonymous 9 |

**Business impact**

| Factor | Options |
| --- | --- |
| Financial damage | less than cost to fix 1, minor 3, significant 7, bankruptcy 9 |
| Reputation damage | minimal 1, loss of major accounts 4, loss of goodwill 5, brand damage 9 |
| Non-compliance | minor 2, clear 5, high profile 7 |
| Privacy violation | one person 3, hundreds 5, thousands 7, millions 9 |

## 2. Calculate

- **Threat agent average** and **vulnerability average**: mean of each group's four factors.
- **Likelihood** = mean of all eight likelihood factors.
- **Technical average** and **business average**: mean of each group's four factors.
- **Impact** = the business average when the repository or user gives real evidence about the business. Otherwise it is the technical average, and the report shows business as `unknown`.

Bands: LOW is 0 to below 3, MEDIUM is 3 to below 6, HIGH is 6 to 9.

## 3. Apply the matrix

| Impact \ Likelihood | LOW | MEDIUM | HIGH |
| --- | --- | --- | --- |
| **HIGH** | Medium | High | Critical |
| **MEDIUM** | Low | Medium | High |
| **LOW** | Low | Low | Medium |

OWASP calls the bottom-left cell "Note". This skill reports four tiers, so it is Low.

## 4. Adjust with threat intelligence

- **KEV-listed and reachable:** Awareness and Ease of Exploit are both 9, and the tier cannot be below High. Ransomware use `Known` raises Motive to 9.
- **KEV-listed but unreachable:** say why it is unreachable, rate it normally, and keep the upgrade recommendation.
- **Weakness class in the top of `dynamic-rules.md`:** note it in the Threat intel field and use the upper end of any honest range for Ease of Exploit.

## 5. Record the CVSS v4.0 baseline

CVSS measures technical severity, not business risk, so it never sets the tier. The report shows it so a reader can see how technical severity and business risk differ.

| Band | Score | Expected action |
| --- | --- | --- |
| Critical | 9.0 to 10.0 | Immediate emergency remediation; deployment halts |
| High | 7.0 to 8.9 | Expedited, ahead of routine feature work |
| Medium | 4.0 to 6.9 | Scheduled within the normal development cycle |
| Low | 0.1 to 3.9 | Tracked in the backlog; revisit if context changes |

- **For a CVE:** report the score and vector from `update-threat-intel.py --cve`, naming its CVSS version.
- **For anything else:** write the v4.0 base vector from the metrics (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA) and give an estimated band, labeled `estimated`. A real v4.0 score needs the official lookup tables, so a decimal score here would be invented.

If the OWASP tier and the CVSS band differ by two or more tiers, explain why in one line under Risk rating.

## Worked example

An unauthenticated SQL injection in a public API holding the PII of 40,000 customers under GDPR:

- Threat agent: skill 5, motive 9, opportunity 9, size 9. Average 8.0.
- Vulnerability: discovery 9, exploit 9, awareness 9, detection 8. Average 8.75.
- Likelihood: 8.4, HIGH.
- Technical: confidentiality 9, integrity 7, availability 5, accountability 7. Average 7.0.
- Business: financial 7, reputation 9, compliance 7, privacy 7. Average 7.5, and the README gives real evidence, so Impact is 7.5, HIGH.
- Matrix: HIGH likelihood and HIGH impact is **Critical**.
