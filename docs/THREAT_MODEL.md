# Threat Model

## Summary

Agents, IDEs, generated code, project files, and child processes are untrusted. The Secret Store, policy engine, broker, redaction engine, and audit writer form the trusted zone.

The preferred model is reference-only execution: untrusted processes receive `secret://` values and a trusted protocol broker performs the operation that requires plaintext. `interpose-exec` is a limited compatibility mode because its subprocess receives resolved arguments.

## Threats

| Threat | Status | Notes |
| --- | --- | --- |
| Prompt injection | Partially Protected | References remain opaque, but an injected agent can attempt unsupported operations or direct egress. |
| Malicious generated code | Partially Protected | The launcher supplies references only. Same-user filesystem and network isolation are not enforced yet. |
| Secret exfiltration through an allowed HTTP target | Partially Protected | Host and method policies are checked before resolution. Fine-grained path/body policy is future work. |
| Inherited environment credentials | Protected in managed sessions | The launcher builds the child environment from an allowlist and injects only declared references. |
| Environment inspection | Protected in managed sessions | Inspection reveals references. Processes launched outside `interpose run` are out of scope. |
| Filesystem inspection | Not Protected Yet | A same-user process may read the local database and master-key file. Run the daemon under a separate OS identity in production. |
| Runtime administrative API access | Not Protected Yet | The local API has no authentication. It must remain on loopback and outside the agent session. |
| `/proc` or process inspection | Partially Protected | Reference-only sessions contain no secret arguments. `interpose-exec` may expose resolved arguments. |
| Process memory inspection | Not Protected Yet | Same-user isolation between the broker and agent is not enforced. |
| Direct network exfiltration | Not Protected Yet | The explicit local transport does not prevent an agent from opening direct sockets. OS egress enforcement remains mandatory. |
| HTTP broker exfiltration | Partially Protected | Destination, method, and scheme policies are enforced before resolution. DNS rebinding and path-level controls remain. |
| HTTPS traffic | Not Protected Yet | `CONNECT` is rejected because an opaque TLS tunnel cannot substitute references safely. |
| HTTP redirects | Protected | Automatic upstream redirects are disabled. |
| URL-encoded references | Protected for query/form HTTP | The broker decodes references, evaluates policy, resolves, and safely re-encodes values. |
| Logs and audit | Protected for known resolved values | Resolved values and resolved URLs are redacted; audit records contain references and metadata only. |
| Tracebacks | Partially Protected | Broker errors are redacted. Untrusted application tracebacks contain references only in managed sessions. |
| Response reflection | Partially Protected | Known resolved values are redacted in headers and bodies. Encoded or transformed reflections may evade exact redaction. |
| DNS exfiltration | Not Protected Yet | DNS is not controlled at the OS layer. |
| Certificate pinning | Not Protected Yet | Future transparent TLS termination will not work for pinned clients without explicit integration. |
| Local cryptographic use | Future | Signing, mTLS, SSH, and SigV4 require operation brokers; returning key material is prohibited. |

## Guarantees

The current implementation guarantees that:

1. no public API or CLI operation returns a stored secret value;
2. broker policies are evaluated before secret resolution;
3. managed child environments contain declared references rather than resolved values;
4. the launcher does not pass `INTERPOSE_MASTER_KEY` or `INTERPOSE_HOME` to children;
5. local secret storage uses authenticated encryption;
6. audit records do not intentionally persist plaintext secrets;
7. HTTP `CONNECT` is rejected instead of creating a false transparent-HTTPS guarantee.
8. the explicit local transport derives the destination from `/proxy/{host}` and defaults external traffic to HTTPS.

## Non-Guarantees

The current implementation does not guarantee protection against:

1. a malicious process running as the same operating-system user as the broker;
2. direct network access that bypasses the local transport;
3. memory scraping of the trusted broker;
4. covert channels, DNS, QUIC, or unmanaged transports;
5. secrets delivered through the limited `interpose-exec` compatibility mode;
6. SDKs that require plaintext locally to validate, derive, encrypt, or sign.
