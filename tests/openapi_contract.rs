use std::collections::BTreeSet;

#[test]
fn openapi_is_valid_and_covers_the_public_router() {
    let source = include_str!("../openapi.yaml");
    let document: serde_yaml::Value =
        serde_yaml::from_str(source).expect("conversation OpenAPI must be valid YAML");
    assert_eq!(document["openapi"].as_str(), Some("3.1.0"));

    let paths = document["paths"]
        .as_mapping()
        .expect("OpenAPI paths must be an object");
    let actual = paths
        .keys()
        .map(|key| key.as_str().expect("path key must be a string"))
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "/healthz",
        "/readyz",
        "/metrics",
        "/v1/profile",
        "/v1/auth/challenges",
        "/v1/auth/sessions",
        "/v1/auth/delegations/{delegation_id}",
        "/v1/conversations/resolve",
        "/v1/conversations/{conversation_id}",
        "/v1/conversations/{conversation_id}/messages",
        "/v1/conversations/{conversation_id}/acknowledgements",
        "/v1/conversations/{conversation_id}/events",
    ]);
    assert_eq!(actual, expected);

    let events = &document["paths"]["/v1/conversations/{conversation_id}/events"]["get"];
    assert!(events["security"].is_sequence());
    assert!(events["responses"]["200"]["content"]["text/event-stream"].is_mapping());
    assert_eq!(
        events["parameters"][2]["schema"]["maximum"].as_u64(),
        Some(100)
    );

    let metrics = &document["paths"]["/metrics"]["get"];
    assert!(metrics["responses"]["200"]["content"]["text/plain"].is_mapping());
    assert_eq!(
        document["components"]["schemas"]["SubjectRef"]["additionalProperties"].as_bool(),
        Some(false)
    );
    assert_eq!(
        document["components"]["schemas"]["Conversation"]["properties"]["snapshot"]["$ref"]
            .as_str(),
        Some("#/components/schemas/SubjectSnapshot")
    );
    assert!(document["components"]["schemas"]["MessagePart"]["oneOf"].is_sequence());
    for strict_schema in [
        "ChallengeRequest",
        "SessionRequest",
        "ResolveConversationRequest",
        "SubmitMessageRequest",
        "Message",
        "ConversationProfile",
    ] {
        assert_eq!(
            document["components"]["schemas"][strict_schema]["additionalProperties"].as_bool(),
            Some(false),
            "{strict_schema} must reject unknown fields"
        );
    }
    assert_eq!(
        document["components"]["schemas"]["SubmitMessageRequest"]["properties"]["key_epoch"]
            ["maximum"]
            .as_u64(),
        Some(i64::MAX as u64)
    );
}
