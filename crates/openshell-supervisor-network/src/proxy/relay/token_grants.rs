// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::token_grant_injection::test_support::TokenGrantTestFixture;
use crate::opa::NetworkInput;
use openshell_core::provider_credentials::ProviderCredentialState;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");
const KEY: &str = "tools.example.test\t443\t/mcp\tprovider:access_token";
const OTHER_KEY: &str = "tools.example.test\t443\t/other\tother:access_token";

struct Setup {
    engine: Arc<OpaEngine>,
    ctx: L7EvalContext,
    fixture: TokenGrantTestFixture,
    after_forward: Option<Box<dyn Fn(usize) + Send>>,
}

fn policy_data(protocol: &str, multiple: bool) -> String {
    let rules = match protocol {
        "mcp" => {
            "          - allow: {method: initialize}\n          - allow: {method: tools/list}\n          - allow: {method: tools/call, tool: read_status}"
        }
        "json-rpc" => "          - allow: {method: tools/list}",
        "graphql" => "          - allow: {operation_type: query, fields: [viewer]}",
        "rest" => "          - allow: {method: POST, path: /mcp}",
        _ => panic!("unsupported test protocol"),
    };
    let mcp = if protocol == "mcp" {
        "        mcp:\n          versions: [\"2025-03-26\", \"2025-11-25\", \"2026-07-28\"]\n"
    } else {
        ""
    };
    let other = if multiple {
        "      - host: tools.example.test\n        port: 443\n        path: /other\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: {method: POST, path: /other}\n"
    } else {
        ""
    };
    format!(
        "network_policies:\n  tools:\n    name: tools\n    endpoints:\n      - host: tools.example.test\n        port: 443\n        path: /mcp\n        protocol: {protocol}\n        enforcement: enforce\n{mcp}        rules:\n{rules}\n{other}    binaries:\n      - {{path: /usr/bin/python3}}\n"
    )
}

fn setup(protocol: &str, multiple: bool, token: std::result::Result<&str, &str>) -> Setup {
    let fixture = match token {
        Ok(token) => TokenGrantTestFixture::success(KEY, token),
        Err(error) => TokenGrantTestFixture::failure(KEY, error),
    };
    Setup {
        engine: Arc::new(
            OpaEngine::from_strings(POLICY, &policy_data(protocol, multiple)).unwrap(),
        ),
        ctx: L7EvalContext {
            host: "tools.example.test".into(),
            port: 443,
            request_default_port: Some(443),
            policy_name: "tools".into(),
            binary_path: "/usr/bin/python3".into(),
            dynamic_credentials: Some(fixture.dynamic_credentials()),
            token_grant_resolver: Some(fixture.resolver()),
            ..Default::default()
        },
        fixture,
        after_forward: None,
    }
}

fn request(path: &str, body: &str, headers: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: tools.example.test\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn tool(name: &str) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{}}}).to_string()
}

async fn read_message<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<String> {
    let mut message = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap() == 0 {
            assert!(message.is_empty(), "incomplete HTTP headers: {message}");
            return None;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>().unwrap();
        }
        message.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    message.push_str(std::str::from_utf8(&body).unwrap());
    Some(message)
}

// Exercise the production dispatch boundary, including its single/multi-endpoint
// choice. The upstream captures complete HTTP requests; the resolver is in-memory.
async fn exchange(
    setup: Setup,
    requests: &[String],
) -> (Vec<String>, Vec<String>, TokenGrantTestFixture) {
    let Setup {
        engine,
        ctx,
        fixture,
        after_forward,
    } = setup;
    let input = NetworkInput {
        host: ctx.host.clone(),
        port: ctx.port,
        binary_path: PathBuf::from(&ctx.binary_path),
        binary_sha256: "unused".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };
    let (configs, generation) = engine
        .query_endpoint_configs_with_generation(&input)
        .unwrap();
    let configs = configs
        .iter()
        .map(|config| crate::l7::parse_l7_config(config).unwrap())
        .collect();
    let evaluator = Box::new(engine.clone_engine_for_tunnel(generation).unwrap());
    let (app, mut client) = tokio::io::duplex(16_384);
    let (mut upstream, server) = tokio::io::duplex(16_384);
    let relay = tokio::spawn(async move {
        relay_http_stream(
            &mut client,
            &mut upstream,
            RelayContext {
                request: &ctx,
                policy: PreparedHttpPolicy::Inspect { configs, evaluator },
                middleware_engine: &engine,
            },
        )
        .await
    });
    let upstream = tokio::spawn(async move {
        let mut server = BufReader::new(server);
        let mut forwarded = Vec::new();
        while let Some(message) = read_message(&mut server).await {
            forwarded.push(message);
            if let Some(after_forward) = &after_forward {
                after_forward(forwarded.len());
            }
            server
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
        forwarded
    });
    let mut app = BufReader::new(app);
    let mut responses = Vec::new();
    for request in requests {
        app.get_mut().write_all(request.as_bytes()).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), read_message(&mut app))
            .await
            .unwrap();
        let Some(response) = response else { break };
        responses.push(response);
    }
    drop(app);
    let result = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        assert!(
            error
                .downcast_ref::<crate::l7::rest::CredentialUnavailableError>()
                .is_some(),
            "{error:?}"
        );
    }
    let forwarded = tokio::time::timeout(Duration::from_secs(5), upstream)
        .await
        .unwrap()
        .unwrap();
    (responses, forwarded, fixture)
}

#[tokio::test]
async fn admitted_protocols_authenticate_through_single_and_multiple_endpoint_dispatch() {
    for multiple in [false, true] {
        for protocol in ["mcp", "json-rpc", "graphql", "rest"] {
            let body = if protocol == "graphql" {
                r#"{"query":"query { viewer { login } }"}"#
            } else {
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#
            };
            let wire = request(
                "/mcp",
                body,
                "MCP-Protocol-Version: 2025-11-25\r\nAuthorization: Bearer stale\r\nauthorization: duplicate\r\n",
            );
            let (responses, forwarded, fixture) =
                exchange(setup(protocol, multiple, Ok("grant-token")), &[wire]).await;
            assert!(
                responses[0].starts_with("HTTP/1.1 204"),
                "{protocol}: {responses:?}"
            );
            assert_eq!(forwarded.len(), 1);
            assert_eq!(forwarded[0].matches("Bearer grant-token").count(), 1);
            assert!(!forwarded[0].contains("stale"));
            assert!(!forwarded[0].contains("duplicate"));
            assert!(forwarded[0].ends_with(body));
            assert!(!responses[0].contains("grant-token"));
            fixture.assert_one_request(KEY);
        }
    }
}

#[tokio::test]
async fn denied_tool_and_mixed_batch_never_resolve_or_forward() {
    for multiple in [false, true] {
        for body in [
            tool("delete_resource"),
            format!("[{},{}]", tool("read_status"), tool("delete_resource")),
        ] {
            let wire = request("/mcp", &body, "MCP-Protocol-Version: 2025-03-26\r\n");
            let (responses, forwarded, fixture) =
                exchange(setup("mcp", multiple, Ok("grant-token")), &[wire]).await;
            assert!(responses[0].starts_with("HTTP/1.1 403"));
            assert!(forwarded.is_empty());
            fixture.assert_no_requests();
        }
    }
}

#[tokio::test]
async fn allowed_tools_initialize_and_receive_streams_authenticate() {
    for multiple in [false, true] {
        for wire in [
            request(
                "/mcp",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            ),
            request(
                "/mcp",
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
                "",
            ),
            request("/mcp", "", "MCP-Protocol-Version: 2025-11-25\r\n").replacen("POST", "GET", 1),
        ] {
            let (responses, forwarded, fixture) =
                exchange(setup("mcp", multiple, Ok("grant-token")), &[wire]).await;
            assert!(responses[0].starts_with("HTTP/1.1 204"), "{responses:?}");
            assert_eq!(forwarded.len(), 1);
            assert!(forwarded[0].contains("Bearer grant-token"));
            fixture.assert_one_request(KEY);
        }
    }
}

#[tokio::test]
async fn grant_errors_missing_resolver_and_ambiguity_fail_closed() {
    for multiple in [false, true] {
        for case in ["issuer", "header", "missing", "ambiguous"] {
            let mut setup = setup(
                "mcp",
                multiple,
                match case {
                    "issuer" => Err("issuer echoed secret-token"),
                    "header" => Ok("secret-token\r\nX-Leak: value"),
                    _ => Ok("secret-token"),
                },
            );
            if case == "missing" {
                setup.ctx.token_grant_resolver = None;
            }
            if case == "ambiguous" {
                let credential = setup.fixture.dynamic_credentials().read().unwrap()[KEY].clone();
                setup.fixture.add_credential(
                    "tools.example.test\t443\t/mcp\tother:access_token",
                    credential,
                    Ok("secret-token"),
                );
            }
            let wire = request(
                "/mcp",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            );
            let (responses, forwarded, fixture) = exchange(setup, &[wire]).await;
            assert!(
                responses[0].starts_with("HTTP/1.1 502"),
                "{case}: {responses:?}"
            );
            assert!(!responses[0].contains("secret-token"));
            assert!(forwarded.is_empty());
            if matches!(case, "missing" | "ambiguous") {
                fixture.assert_no_requests();
            } else {
                fixture.assert_one_request(KEY);
            }
        }
    }
}

#[tokio::test]
async fn keep_alive_alternates_endpoint_bound_credentials() {
    let setup = setup("mcp", true, Ok("mcp-token"));
    let mut credential = setup.fixture.dynamic_credentials().read().unwrap()[KEY].clone();
    credential.token_grant.as_mut().unwrap().audience = "other-api".into();
    setup
        .fixture
        .add_credential(OTHER_KEY, credential, Ok("other-token"));
    let (responses, forwarded, fixture) = exchange(
        setup,
        &[
            request(
                "/mcp",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            ),
            request("/other", "{}", ""),
            request(
                "/mcp?view=summary",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            ),
        ],
    )
    .await;
    assert_eq!(responses.len(), 3);
    assert_eq!(forwarded.len(), 3);
    for (message, token) in forwarded
        .iter()
        .zip(["mcp-token", "other-token", "mcp-token"])
    {
        assert!(message.contains(&format!("Bearer {token}")));
        assert_eq!(message.matches("Authorization:").count(), 1);
    }
    fixture.assert_requested_keys(&[KEY, OTHER_KEY, KEY]);
}

#[tokio::test]
async fn provider_refresh_on_keep_alive_uses_current_revision() {
    for multiple in [false, true] {
        let mut setup = setup("mcp", multiple, Ok("stale-connection-token"));
        let credentials = setup.fixture.dynamic_credentials().read().unwrap().clone();
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::new(),
            HashMap::new(),
            credentials.clone(),
        );
        let key1 = KEY.replace("\tprovider:", "\trev:1\tprovider:");
        let key2 = KEY.replace("\tprovider:", "\trev:2\tprovider:");
        setup
            .fixture
            .add_credential(&key1, credentials[KEY].clone(), Ok("first-token"));
        setup
            .fixture
            .add_credential(&key2, credentials[KEY].clone(), Ok("second-token"));
        setup.ctx.provider_credentials = Some(state.clone());
        setup.after_forward = Some(Box::new(move |count| {
            if count == 1 {
                state.install_environment(2, HashMap::new(), HashMap::new(), credentials.clone());
            }
        }));
        let wire = request(
            "/mcp",
            &tool("read_status"),
            "MCP-Protocol-Version: 2025-11-25\r\n",
        );
        let (responses, forwarded, fixture) = exchange(setup, &[wire.clone(), wire]).await;
        assert_eq!(responses.len(), 2);
        assert_eq!(forwarded.len(), 2);
        assert!(forwarded[0].contains("Bearer first-token"));
        assert!(forwarded[1].contains("Bearer second-token"));
        fixture.assert_requested_keys(&[&key1, &key2]);
    }
}

#[tokio::test]
async fn independent_contexts_keep_credentials_separate() {
    let requests = [request(
        "/mcp",
        &tool("read_status"),
        "MCP-Protocol-Version: 2025-11-25\r\n",
    )];
    let (a, b) = tokio::join!(
        exchange(setup("mcp", true, Ok("sandbox-a-token")), &requests),
        exchange(setup("mcp", true, Ok("sandbox-b-token")), &requests)
    );
    assert!(a.1[0].contains("sandbox-a-token"));
    assert!(!a.1[0].contains("sandbox-b-token"));
    assert!(b.1[0].contains("sandbox-b-token"));
    assert!(!b.1[0].contains("sandbox-a-token"));
    a.2.assert_one_request(KEY);
    b.2.assert_one_request(KEY);
}

#[tokio::test]
async fn provider_update_during_grant_prevents_upstream_write() {
    struct UpdatingResolver(ProviderCredentialState);
    impl crate::l7::token_grant_injection::TokenGrantResolver for UpdatingResolver {
        fn obtain<'a>(
            &'a self,
            _request: crate::l7::token_grant_injection::TokenGrantRequest<'a>,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
            Box::pin(async move {
                self.0
                    .install_environment(2, HashMap::new(), HashMap::new(), HashMap::new());
                Ok("revoked-token".into())
            })
        }
    }
    for multiple in [false, true] {
        let mut setup = setup("mcp", multiple, Ok("unused"));
        let credentials = setup.fixture.dynamic_credentials().read().unwrap().clone();
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::new(),
            HashMap::new(),
            credentials,
        );
        setup.ctx.provider_credentials = Some(state.clone());
        setup.ctx.token_grant_resolver = Some(Arc::new(UpdatingResolver(state)));
        let (_, forwarded, _) = exchange(
            setup,
            &[request(
                "/mcp",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            )],
        )
        .await;
        assert!(forwarded.is_empty());
    }
}

#[tokio::test]
async fn middleware_transformation_is_revalidated_before_grant() {
    struct Rewriter(String);

    #[tonic::async_trait]
    impl openshell_core::middleware::InProcessMiddleware for Rewriter {
        async fn describe(&self) -> openshell_core::proto::MiddlewareManifest {
            openshell_core::proto::MiddlewareManifest {
                name: "test/rewriter".into(),
                service_version: "test".into(),
                bindings: vec![openshell_core::proto::MiddlewareBinding {
                    operation: openshell_core::proto::SupervisorMiddlewareOperation::HttpRequest
                        as i32,
                    phase: openshell_core::proto::SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 8192,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-middleware",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(&self, _name: &str, _config: &prost_types::Struct) -> Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            request: openshell_core::middleware::HttpRequestView<'_>,
        ) -> Result<openshell_core::proto::HttpRequestResult> {
            assert!(!format!("{:?}", request.headers()).contains("grant-token"));
            Ok(openshell_core::proto::HttpRequestResult {
                decision: openshell_core::proto::Decision::Allow as i32,
                body: self.0.as_bytes().to_vec(),
                has_body: true,
                ..Default::default()
            })
        }
    }

    for multiple in [false, true] {
        for replacement in ["read_status", "delete_resource"] {
            let mut setup = setup("mcp", multiple, Ok("grant-token"));
            let policy = format!(
                "network_middlewares:\n  rewriter:\n    middleware: test/rewriter\n    on_error: fail_closed\n    endpoints:\n      include: [tools.example.test]\n{}",
                policy_data("mcp", multiple)
            );
            setup.engine = Arc::new(OpaEngine::from_strings(POLICY, &policy).unwrap());
            setup.engine.set_middleware_runner_for_tests(
                openshell_supervisor_middleware::ChainRunner::new(Arc::new(Rewriter(tool(
                    replacement,
                )))),
            );
            let wire = request(
                "/mcp",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            );
            let (responses, forwarded, fixture) = exchange(setup, &[wire]).await;
            if replacement == "delete_resource" {
                assert!(responses[0].starts_with("HTTP/1.1 403"));
                assert!(forwarded.is_empty());
                fixture.assert_no_requests();
            } else {
                assert!(responses[0].starts_with("HTTP/1.1 204"));
                assert_eq!(forwarded.len(), 1);
                assert!(forwarded[0].contains("Bearer grant-token"));
                fixture.assert_one_request(KEY);
            }
        }
    }
}

#[tokio::test]
async fn sessionless_mcp_authenticates_admitted_tools_and_discovery() {
    for multiple in [false, true] {
        for method in ["tools/list", "tools/call"] {
            let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":{
                "name":"read_status", "arguments":{}, "_meta":{
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities":{}
                }
            }})
            .to_string();
            let name = if method == "tools/call" {
                "Mcp-Name: read_status\r\n"
            } else {
                ""
            };
            let wire = request(
                "/mcp",
                &body,
                &format!("MCP-Protocol-Version: 2026-07-28\r\nMcp-Method: {method}\r\n{name}"),
            );
            let (responses, forwarded, fixture) =
                exchange(setup("mcp", multiple, Ok("grant-token")), &[wire]).await;
            assert!(responses[0].starts_with("HTTP/1.1 204"), "{responses:?}");
            assert!(forwarded[0].contains("Bearer grant-token"));
            fixture.assert_one_request(KEY);
        }
    }
}

#[tokio::test]
async fn mismatched_authority_never_obtains_endpoint_credentials() {
    for multiple in [false, true] {
        for authority in ["other.example.test", "tools.example.test:8443"] {
            let wire = request(
                "/mcp",
                &tool("read_status"),
                "MCP-Protocol-Version: 2025-11-25\r\n",
            )
            .replace(
                "Host: tools.example.test\r\n",
                &format!("Host: {authority}\r\n"),
            );
            let (responses, forwarded, fixture) =
                exchange(setup("mcp", multiple, Ok("grant-token")), &[wire]).await;
            assert!(responses[0].starts_with("HTTP/1.1 403"));
            assert!(forwarded.is_empty());
            fixture.assert_no_requests();
        }
    }
}
