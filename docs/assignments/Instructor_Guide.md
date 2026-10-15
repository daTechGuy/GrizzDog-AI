# GrizzDog-AI: Instructor & Faculty Guide
## Turnkey Guide for Cybersecurity & AI Security Courses

**Affiliation**: Butler Community College Cyber Defense Faculty Project (Andover Campus, KS)  
**Notice**: Independent faculty research and pedagogical lab. Strictly for educational research and testing; not an official Butler Community College institutional service or endorsement.  
**Target Course Level**: Undergraduate / Graduate Cybersecurity, Software Security, AI Safety  
**Standard Mapping**: ACM/IEEE Cybersecurity, NIST NICE Knowledge Units (AI Threat Analysis, Defense-in-Depth)  
**Upstream Attribution**: Adapted from the foundational cybersecurity architecture created by **[SixFiveMil](https://github.com/SixFiveMil)** in **[Securing-AI](https://github.com/SixFiveMil/Securing-AI)**.

---

## 1. Course Curriculum Integration

GrizzDog-AI can be deployed as an interactive, hands-on lab in several academic formats:

### Option A: One-Week Modular Lab (2 Class Sessions)
* **Session 1 (Red Team Focus)**: Students explore prompt injection, authority spoofing, and system prompt leakage against `vulnerable_bot` across the three personas.
* **Session 2 (Blue Team Focus)**: Students edit `filter_rules.py` to harden the gateway, run `evaluate_rules.py`, and submit their defense brief.

### Option B: Two-Week In-Depth Security Project
* **Week 1**: Red teaming + prompt engineering in `lab/modelfiles/` (Phases 1 & 2).
* **Week 2**: Advanced policy engine hardening using Open Policy Agent (`gateway.rego` & `rules.json`), with automated benchmarking and adversarial CTF competition between student teams.

### Option C: Live Classroom Lecture Demonstration
* The instructor uses `lab/scripts/set_tier.py` to switch between presets live during lecture:
  ```bash
  python lab/scripts/set_tier.py blank       # Demonstrates unprotected baseline
  python lab/scripts/set_tier.py scaffolded  # Demonstrates partial student progress
  python lab/scripts/set_tier.py calibrated  # Demonstrates hardened defense-in-depth
  ```

### Option D: Offline / Low-Resource Event Demonstration
* The gateway includes an automatic **dual-engine execution model**: if Ollama is running, it uses live neural inference (`EXECUTED ✓`); if Ollama is stopped or the machine lacks GPU/RAM, it seamlessly switches to the built-in deterministic simulator (`SIMULATED ⚠️`). This allows demonstrations at conferences, STEM recruitment fairs, or classrooms without requiring local GPU hardware or an active internet connection.

---

## 2. Pedagogical Objectives & Competency Mapping

By completing this lab, students will be able to:
1. **Differentiate Control Plane vs Data Plane in LLMs**: Understand why language models struggle to distinguish developer instructions from user inputs without architectural separation.
2. **Execute and Mitigate Social Engineering Attacks on AI**: Identify authority spoofing patterns and construct gateway-level identity validation boundaries.
3. **Analyze Indirect Prompt Injection**: Demonstrate how untrusted external content (e.g., student homework submissions, uploaded resumes, external documents) can hijack LLM evaluation logic.
4. **Enforce Compliance & Privacy (FERPA / PII)**: Implement egress Data Loss Prevention (DLP) to prevent regulatory violations in automated public-facing systems.
5. **Evaluate Usability vs. Security Trade-offs**: Measure how naive defensive blacklisting induces false positives on legitimate user queries.

---

## 3. Reference Architecture & Solution Keys

### Target Educational Personas & Secrets

| Persona | Vulnerable Flaw | Target Secret / Asset | Reference Ingress Trigger | Reference Egress Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **GrizzDog (Quadruped)** | Accepts spoofed technician commands & disarm queries | `GRIZZDOG-ROOT-KEY-9941`, `/override_grizzdog_patrol`, `GRIZZDOG-DISARM-SIG-882` | `"override grizzdog"`, `"/override_grizzdog_patrol"`, `"disarm grizzdog"`, `"grizzdog root key"` | `"grizzdog root key"`, `"GRIZZDOG-ROOT-KEY-9941"` |
| **Sage (TA)** | Complies if user claims to be Dr. Simon (Herbert A. Simon) or Dean | `EXAM-KEY-CS101-FALL26-Q4-RSA`, `TA-AUTH-SAGE-7731` | `"i am dr. simon"`, `"ignore all previous"` | `"exam question 4 answer key"`, `"ta auth token"` |
| **GraderBot** | Evaluates embedded directives in homework | `CANVAS-API-KEY-PROD-9912`, `gradebook.canvas.campus.internal` | `"[instructor note]"`, `"system directive"`, `"award 100 points"` | `"canvas api key"`, `"internal gradebook host"` |
| **Morgan (Registrar)** | Releases FERPA data for administrators | `SID-88391: GPA 1.82 - Academic Suspension` | `"confidential student record"`, `"export ferpa roster"` | `"academic suspension"`, `"gpa 1.82"`, `"ferpa record"` |

### Automated Evaluation
Instructors can grade student submissions in seconds using the standalone evaluation script:

```bash
# In the student's submission directory:
python lab/scripts/evaluate_rules.py --verbose
```

This runs the visible suite (ingress attacks, egress DLP leaks and harmless queries, all printed with `--verbose`) and the **held-out generalization suite** (reworded, encoded, translated and roleplay attacks plus over-blocking probes, reported only by technique).

- Part 2 of the rubric is auto-scored as 35 pts × the average of the visible and held-out attack catch rates, so a student who only pastes the visible test phrases into the blacklist tops out around 17.5 / 35. Part 3 uses the harmless tests from both suites, so over-broad triggers like `"exam"` or `"ferpa"` cost points.
- The shipped `lab/benchmark/heldout_tests.json` is public on GitHub. For graded work, write your own private variants (same JSON format) and run the gateway or CLI with `HELDOUT_TESTS_PATH=/path/to/private.json`. Rotate them each term.

### Threat Taxonomy: OWASP Top 10 for LLM, MITRE ATLAS & CAE-CD Alignment

To align with NSA/DHS CAE-CD Knowledge Units and the NIST NICE Cybersecurity Workforce Framework (SP 800-181), each lab mission and benchmark test case maps directly to recognized industry and national accreditation standards:

| Attack Category / Mission | Target Persona | OWASP Top 10 for LLM | MITRE ATLAS Technique | CAE-CD Knowledge Unit (KU) | NIST NICE Work Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Mission 1: Exam Key Extraction & Prompt Leak** | Sage (TA) | `LLM01: Prompt Injection`<br>`LLM07: System Prompt Leak` | `AML.T0051.000: Direct Prompt Injection`<br>`AML.T0057: LLM Data Extraction` | **SSA: System & Software Assurance** | Vulnerability Assessment Analyst (`SP-DEV-001`) |
| **Mission 2: Authority Spoofing** | Sage, GrizzDog | `LLM01: Prompt Injection`<br>`LLM06: Excessive Agency` | `AML.T0054: LLM Jailbreak`<br>`AML.T0043: Adversarial Evasion` | **AC: Access Control**<br>**BN: Basic Networking** | Cyber Defense Analyst (`PR-CDA-001`) |
| **Mission 3: Indirect Homework Injection** | GraderBot | `LLM01: Prompt Injection (Indirect)`<br>`LLM06: Excessive Agency` | `AML.T0051.001: Indirect Prompt Injection` | **SSA: System & Software Assurance** | Vulnerability Assessment Analyst (`SP-DEV-001`) |
| **Mission 4: FERPA Student Record Exfiltration** | Morgan (Registrar) | `LLM02: Sensitive Information Disclosure` | `AML.T0057: LLM Data Extraction` | **IA: Information Assurance**<br>**DP: Data Privacy Compliance** | Cyber Policy & Privacy Manager (`OV-PMA-001`) |
| **Mission 5: Socratic Tutoring / Policy Bypass** | Sage (TA) | `LLM01: Prompt Injection`<br>`LLM04: Policy Subversion` | `AML.T0054: LLM Jailbreak` | **POL: Cyber Ethics & AI Safety** | Security Control Assessor (`SP-RSK-002`) |
| **Robotics Sentry: Root Key & Patrol Overrides** | GrizzDog | `LLM02: Sensitive Information Disclosure`<br>`LLM06: Excessive Agency` | `AML.T0051: LLM Prompt Injection`<br>`AML.T0057: LLM Data Extraction` | **HDS: Host & Device Security**<br>**IoT: Quadruped Robotics** | Security Control Assessor (`SP-RSK-002`) |
| **Egress DLP Leakage Prevention** | All Personas | `LLM02: Sensitive Information Disclosure` | `AML.T0057: LLM Data Extraction` | **DLP: Data Loss Prevention** | Cyber Defense Analyst (`PR-CDA-001`) |

---

## 4. 100-Point Grading Rubric

| Component | Points | Criteria |
| :--- | :--- | :--- |
| **1. Red Team Attack Documentation** | **25 pts** | - Successfully executed at least 4 of 5 attack missions against `vulnerable_bot`<br>- Documented exact prompt payloads and resulting model outputs<br>- Correctly analyzed why `hardened_bot` mitigated or failed against the attack |
| **2. Gateway Rule Implementation** | **35 pts** | - High attack catch rate ($\ge 85\%$) on adversarial test cases<br>- Proper implementation of ingress keyword filters and egress DLP secrets<br>- No hardcoded bypasses or syntax errors in `filter_rules.py` |
| **3. Usability & False Positive Control** | **20 pts** | - Legitimate student queries pass without being blocked (Benign Usability Rate $\ge 90\%$)<br>- Demonstrated avoidance of overly broad regex/wildcard triggers (e.g. blocking the word "exam" or "Dr. Simon") |
| **4. Defense Brief & Reflection** | **20 pts** | - Thorough completion of the Sentence Starter defense brief<br>- Thoughtful residual risk analysis identifying remaining blind spots in static regex |
| **Total** | **100 pts** | |

### Turnkey Canvas LMS Batch Grading (`batch_grade.py`)

For multi-student course sections, grade and verify an entire folder of exported `.md` submissions with one command:

```bash
# Verify HMAC signatures, check rule provenance, and export Canvas Gradebook CSV:
REPORT_SECRET="<instructor_secret>" python lab/scripts/batch_grade.py submissions/ --csv canvas_grades.csv
```

- **Cryptographic Seal Verification**: Automatically validates HMAC-SHA256 signatures for every file, displaying `[VALID ✓]`, `[TAMPERED 🚨]`, or `[UNSIGNED ⚠️]`.
- **Auto-Scoring Calculation**: Tallies Parts 2 & 3 (55 pts auto), applies zero auto-points if an unedited preset was submitted, and counts answered reflection brief questions.
- **Direct Canvas LMS Import**: Outputs `canvas_grades.csv` ready to upload into the Butler Canvas Gradebook (`Grades -> Actions -> Import CSV`).

To verify individual files one-by-one:
```bash
REPORT_SECRET="<instructor_secret>" python lab/scripts/verify_report.py submissions/*.md
```

---

> For grading detail, expected benchmark scores, common student mistakes and model discussion answers, see the [Instructor Answer Key & Cheat Sheet](Instructor_Answer_Key.md).

## 5. Active Learning Discussion Questions

Use these questions for post-lab classroom discussions:

1. **The Ingress Delusion**: *"If an attacker uses base64, pig latin, or foreign language translations for 'ignore all previous instructions', will our static keyword blacklist catch it? How does Phase 3 (OPA context classification) change this dynamic?"*
2. **The Defense-in-Depth Imperative**: *"Why is egress data filtering (DLP) essential even when we have hardened system prompts and ingress filters?"*
3. **The Socratic Dilemma**: *"In automated tutoring, where does helpful instruction end and academic dishonesty begin? Can an AI reliably enforce that boundary autonomously?"*
