# Intelligent Feedback Engine

Component 3 is developed as a standalone Spring Boot prototype before full
system integration. It consumes mock security-event data from Component 1 and
mock behaviour-history data from Component 2.

## Build and test

From this directory, run:

```text
mvn test
```

The service is configured to use port `8083` when it is started with
`mvn spring-boot:run`.

The current prototype includes mock security-event and behaviour-history
models, severity scoring, and behaviour-aware feedback escalation. Repeated
ignored warnings increase feedback severity, while consistent fixes reduce
severity without crossing the `INFO` or `CRITICAL` boundaries.

It also provides secure-coding recommendation templates for each supported
vulnerability category, including practical guidance and secure examples.

For a browser demonstration using mock data, start the service and open
`http://localhost:8083/`. The page shows the original score, behaviour-based
escalation, and SQL-injection recommendation. The raw JSON is available at
`http://localhost:8083/api/demo`. The demo also shows the monitored file, the
vulnerable code, the detected error, and a corrected secure version.
