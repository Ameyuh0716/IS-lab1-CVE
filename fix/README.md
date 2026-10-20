# Fixes (submission item 4)

This folder contains every artifact that was changed to eliminate **CVE-2022-22963** in the
reproduced environment, together with the files that define that environment.

```
fix/
├── README.md                        # this file
└── CVE-2022-22963/
    ├── Dockerfile                   # multi-stage build of the sample app on the patched library
    ├── docker-compose.yml           # published on 8081, runs next to the vulnerable one on 8080
    ├── pom.xml                      # spring-cloud-function 3.2.3 (vulnerable: 3.2.2)
    └── src/main/
        ├── java/vulhub/springcloudfunction/SpringCloudFunctionSampleApplication.java
        └── resources/application.properties
```

## What was changed and why

| File | Change | Reason |
|---|---|---|
| `pom.xml` | `spring-cloud-function-web` **3.2.2 → 3.2.3** | 3.2.3 contains the upstream fix (`RoutingFunction` no longer evaluates the header expression with `StandardEvaluationContext`) |
| `Dockerfile` | new, builds the sample application on top of the patched dependency | makes the fix reproducible and reviewable instead of pulling a pre-built `vulhub` tag that does not exist for 3.2.3 |
| `docker-compose.yml` | new, maps **8081** → 8080 | allows vulnerable (8080) and fixed (8081) instances to run at the same time for a side-by-side comparison |
| `src/...Application.java`, `application.properties` | new, minimal `uppercase` function over WebFlux | reproduces the same sample app as the vulnerable image so the only variable is the library version |

No configuration knob alone removes this vulnerability: the exploit works on the default
configuration because `RoutingFunction` genuinely evaluates the routing header. The fix must change
the code path (which the library upgrade does) — see §9 of the top-level `README.md`.

## Reproduce the fix

```bash
docker compose -f fix/CVE-2022-22963/docker-compose.yml up --build -d
./exploit/poc.sh fix/CVE-2022-22963/docker-compose.yml spring-fixed 8081 /tmp/success
# [*] 1) sanity: TEST
# [+] NOT EXPLOITABLE: /tmp/success was not created
```

Expected container log line:

```
org.springframework.expression.spel.SpelEvaluationException: EL1005E: Type cannot be found 'java.lang.Runtime'
```

## Rollback

If the vulnerable behaviour is needed again for demonstration, change
`<spring-cloud-function.version>` back to `3.2.2` and rebuild. Never deploy that build outside an
isolated lab network.
