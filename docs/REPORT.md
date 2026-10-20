<div align="center">

# Hangzhou Dianzi University
## Faculty of Computer Science and Technology

<br><br><br>

# Laboratory Work No. 1

## Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

<br>

**Variant:** CVE-2022-22963 (Spring Cloud Function SpEL Code Injection)

<br><br><br>

**Surname and Name:** Yao Jiangyu
**HDU number:** 23320115

<br><br><br>

**2026**

</div>

---

## Purpose of the work

To gain practical experience in building a secure backend application with automated vulnerability
checking, and in analysing and remediating a real-world vulnerability in a controlled environment:
designing protection against the OWASP Top 10, integrating security tools into CI/CD, reproducing a
known CVE, identifying its root cause, and verifying the fix.

## 1. Deliverables

| # | Required item | Location |
|---|---|---|
| 1 | Public git repository | `git@github.com:Ameyuh0716/IS-lab1-CVE.git` |
| 2 | README.md with description, security measures, scanner screenshots, CVE analysis, root cause, fix, proof | [`../README.md`](../README.md) |
| 3 | Link to last successful pipeline run | <https://github.com/Ameyuh0716/IS-lab1-CVE/actions/runs/39454630564> |
| 4 | Folder with the fixes | [`../fix/`](../fix/) |

## 2. Summary

**The API** (`secure-api/`, Java 17 + Spring Boot 4.1.1) exposes `POST /auth/login`,
`GET /api/data`, and the custom endpoints `GET /api/posts`, `POST /api/posts`,
`DELETE /api/posts/{id}`, `GET /api/me`. Data lives in an in-memory H2 database accessed through
Spring Data JPA.

**Implemented protections**

| Threat | Measure |
|---|---|
| SQL injection (A03) | Parameterized JPQL and derived queries only; no string concatenation; allow-list validation as a second layer |
| XSS (A03) | HTML escaping of all user input at ingress (`HtmlUtils.htmlEscape`); JSON-only responses; CSP, `nosniff`, `DENY` frame options; strict CORS allow-list |
| Broken authentication (A07) | BCrypt (cost 12) password hashes; HS256 JWT with `iss`/`iat`/`exp`; stateless verification filter; `401`/`403` separation; role-based authorization; lockout after 5 failed logins; constant-time login path |

**CI/CD** (`.github/workflows/ci.yml`) runs on every push and pull request:
`mvn test` (10 security integration tests) → SpotBugs SAST (fails on Medium+) → OSV.dev
SCA gate (fails on HIGH/CRITICAL) → OWASP Dependency-Check SCA (fails on CVSS ≥ 7, enabled when the
`NVD_API_KEY` secret is configured), with all reports uploaded as artifacts.

**SCA-driven remediation.** The first scan of the original Spring Boot 3.3.5 dependency set found 87
advisories (9 critical, 30 high) in Tomcat, Spring Framework/Security and Jackson. The build was
moved to Spring Boot 4.1.1 and the remaining components were pinned to patched releases
(Tomcat 11.0.25, Jackson 3.1.8 / 2.21.8). A re-scan reports **0 findings across 91 dependencies**
while all 10 tests and SpotBugs still pass — i.e. the "scan → fix → verify" loop is demonstrated,
not just a pipeline that happens to be green.

**CVE-2022-22963.** Spring Cloud Function ≤ 3.2.2 evaluates the request header
`spring.cloud.function.routing-expression` as a SpEL expression using a `StandardEvaluationContext`,
which permits type references and method invocation. An unauthenticated attacker therefore reaches
`T(java.lang.Runtime).getRuntime().exec(...)` and executes arbitrary commands in the application
JVM (CVSS 9.8).

**Reproduction and fix.** The vulhub 3.2.2 image was started on port 8080 and the injection header
created `/tmp/success` inside the container, running as `root`. The fix pins
`spring-cloud-function` 3.2.3, which uses `SimpleEvaluationContext` with a read-only data-binding
accessor for header-supplied expressions; the rebuilt image on port 8081 rejects the identical
request with `EL1005E: Type cannot be found 'java.lang.Runtime'` and no file is created, while the
legitimate `uppercase` function still works.

Detailed explanations, commands and the reasoning behind the fix are in the top-level
[`README.md`](../README.md); the fixes themselves are in [`../fix/`](../fix/).

## 3. Control questions

**1. Why is bcrypt preferable to SHA-256 for password hashing?**
SHA-256 is a general-purpose cryptographic hash designed to be *fast*; a GPU can compute billions of
guesses per second, and the same password always produces the same digest (so rainbow tables work).
BCrypt is deliberately slow and memory-hard-ish (cost factor, default here 12 ⇒ ~2^12 key-setup
iterations), embeds a unique random salt in every hash (identical passwords hash differently), and
its cost can be raised as hardware improves. Hashing a password once with SHA-256 therefore offers
no meaningful resistance to offline cracking, while bcrypt makes each guess expensive.

**2. SAST vs DAST?**
SAST analyses source code or bytecode without running the application (SpotBugs here): it finds
dangerous patterns early, covers all code paths including unreachable ones, and points to the exact
line — but it cannot see runtime configuration and produces false positives. DAST tests a *running*
application from the outside (like an attacker, e.g. OWASP ZAP): it finds real, exploitable behaviour
and configuration issues, but has no source context and can only reach code it can exercise. They
are complementary — SAST catches the flaw, DAST proves the exposure.

**3. How does a JWT work, what does it contain, and how is it verified?**
A JWT is three Base64url segments — `header.payload.signature`. The header names the algorithm
(`HS256`) and type; the payload holds claims (`sub`, `role`, `iss`, `iat`, `exp`); the signature is
`HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)`. The payload is **encoded, not
encrypted** — anyone can read it, so it must never contain secrets. The server verifies by
recomputing the HMAC with its key, comparing signatures in constant time, and checking `iss` and
`exp`; only then does it trust the claims. Since the token is self-contained, protected endpoints
need no server-side session — which is why this API is stateless.

**4. What are the risks of not auditing third-party dependencies?**
Most of a modern application's code is transitive dependencies, and they inherit their CVEs.
Unaudited libraries can bring remote code execution, deserialization flaws, or leaked secrets into
production without a single line of your own code changing (Log4Shell, Spring4Shell,
CVE-2022-22963 are exactly this class). You also lose track of licences and of end-of-life
components that no longer receive patches. Automated SCA in CI turns this into a build-time signal
instead of an incident.

**5. Advantages of Docker + Vulhub over installing vulnerable software directly?**
Isolation (the vulnerable service cannot touch the host), reproducibility (the exact vulnerable
version and configuration are pinned in a compose file), disposability (`down` and the environment
is gone, including any webshell), and safety (no need to expose an intentionally broken service on
the real network). It also makes side-by-side comparison trivial: this work runs the vulnerable
3.2.2 build on 8080 and the fixed 3.2.3 build on 8081 simultaneously.

**6. Vulnerability vs exploit — what was reproduced here?**
A *vulnerability* is the weakness itself: `RoutingFunction` evaluates an untrusted header with a
powerful expression language (CVE-2022-22963). An *exploit* is the concrete technique that abuses
it: sending a POST to `/functionRouter` with
`spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")`.
The CVE is the bug; the crafted HTTP request is the exploit. What was reproduced was the exploit,
to demonstrate the vulnerability.

**7. Why is regression testing critical after a patch?**
A security fix changes behaviour, and the change can break legitimate use — over-restricting input,
altering a code path, or removing a feature callers rely on. Shipping an unusable application is a
different kind of outage, and in practice many organisations delay patches precisely because of this
fear. Verifying that the fixed build still serves `uppercase` normally (and that all 10 API tests
pass) proves the patch is both effective *and* safe to deploy.

**8. Why does the ability to reproduce known CVEs matter for a security specialist?**
It converts a text description into an observable behaviour: you learn the precise trigger, the
preconditions, and the difference between a theoretical score and a real risk — which is what
prioritisation requires. A pentester uses it to validate exposure and to write a credible proof of
concept; a SOC analyst uses it to build detection rules (the `spring.cloud.function.routing-expression`
header is a perfect signature) and to judge alerts; an engineer uses it to verify that a patch
actually closes the hole. Practising on isolated replicas (Vulhub) builds that skill safely.

## 4. Conclusion

The API satisfies all functional and security requirements and is covered by automated SAST/SCA in
CI. CVE-2022-22963 was reproduced end-to-end on Spring Cloud Function 3.2.2, its root cause was
traced to SpEL evaluation of an untrusted header with `StandardEvaluationContext`, and the upstream
fix (3.2.3, `SimpleEvaluationContext`) was verified to block the exploit without breaking normal
functionality.
