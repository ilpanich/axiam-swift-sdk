import Foundation

// The hand-written conveniences around the generated §29 – §32 models (contract 1.54 – 1.57),
// and the local checks the generated surface runs before any I/O.
//
// Kept out of `Generated/` on purpose: the generator (`Scripts/gen_management.py`) owns that
// directory and overwrites it, and these are decisions about how a caller should build a
// request, not facts read from the registry. The generator reaches into this file in exactly
// one way — its `PRECHECKS` table emits a call to a `ManagementChecks` function at the top of
// an operation.

/// Local checks the generated §27 surface runs on a request body before any I/O.
enum ManagementChecks {
    /// §29.2: `ParseSamlSpMetadata` is **exactly one** of `metadata_xml` and `metadata_url`.
    /// Both, or neither, is a local `ValidationError` raised before any request — never a
    /// request the server refuses.
    static func parseSpMetadataExactlyOne(_ body: ParseSamlSpMetadata) throws {
        switch (body.metadataXml, body.metadataURL) {
        case (.some, .none), (.none, .some):
            return
        case (.some, .some):
            throw refusal(
                "saml.parse_sp_metadata",
                "set exactly one of metadata_xml and metadata_url, not both (CONTRACT.md §29.2)")
        case (.none, .none):
            throw refusal(
                "saml.parse_sp_metadata",
                "set exactly one of metadata_xml and metadata_url (CONTRACT.md §29.2)")
        }
    }

    /// The SDK's local validation failure: §27.4 rule 7's `ValidationError`, which this SDK
    /// renders as a `NetworkError` with ``NetworkError/isValidation`` set.
    static func refusal(_ operation: String, _ message: String) -> AxiamError {
        .network(NetworkError("\(operation): \(message)", statusCode: 400, isValidation: true))
    }
}

// MARK: - §29 saml

extension ParseSamlSpMetadata {
    /// A request for the server to fetch the SP's metadata from `url` (`https` only, through
    /// its SSRF guard) — exactly `{"metadata_url": …}`.
    public static func fromURL(_ url: String) -> ParseSamlSpMetadata {
        ParseSamlSpMetadata(metadataURL: url, metadataXml: nil)
    }

    /// A request carrying the SP's metadata document itself (at most 512 KiB) — exactly
    /// `{"metadata_xml": …}`.
    public static func fromXML(_ xml: String) -> ParseSamlSpMetadata {
        ParseSamlSpMetadata(metadataURL: nil, metadataXml: xml)
    }
}

extension SamlServiceProviderInput {
    /// The read-modify-write form §27.4 rule 5 recommends for `update_service_provider`, a
    /// **replacement**: a `getServiceProvider` result turned back into the body, every member
    /// carried over, so changing one field and sending it back preserves the rest.
    ///
    /// The result has no `sign_assertions` member: there is no such switch (§29.2 — the
    /// assertion is always signed).
    public init(copying sp: SamlServiceProvider) {
        self.init(
            acsUrls: sp.acsUrls,
            allowIdpInitiated: sp.allowIdpInitiated,
            allowedGroups: sp.allowedGroups,
            attributeMappings: sp.attributeMappings,
            displayName: sp.displayName,
            enabled: sp.enabled,
            encryptAssertions: sp.encryptAssertions,
            entityID: sp.entityID,
            nameIDFormat: sp.nameIDFormat,
            signResponses: sp.signResponses,
            sloBinding: sp.sloBinding,
            sloURL: sp.sloURL,
            spEncryptionCertPEM: sp.spEncryptionCertPEM,
            spSigningCertPEM: sp.spSigningCertPEM,
            wantAuthnRequestsSigned: sp.wantAuthnRequestsSigned)
    }
}

// MARK: - §30 directory

extension SetDirectoryConfig {
    /// The read-modify-write form for `directory.set`, a **replacement**: a `directory.get`
    /// result turned back into the body, every member carried over.
    ///
    /// `bindSecret` is left `nil` — absent keeps the stored secret, unless the write moves the
    /// connection (`url`, `startTLS`, `bindDn` or `trustAnchorsPEM`), which then requires it
    /// again (§30.3 rule 2). `DirectoryConfig` carries no secret to copy, and this SDK holds
    /// none.
    public init(copying config: DirectoryConfig) {
        self.init(
            baseDn: config.baseDn,
            bindDn: config.bindDn,
            bindSecret: nil,
            enabled: config.enabled,
            groupBaseDn: config.groupBaseDn,
            groupFilter: config.groupFilter,
            groupMappings: config.groupMappings,
            groupMemberAttribute: config.groupMemberAttribute,
            groupNestingDepth: config.groupNestingDepth,
            jitProvisioning: config.jitProvisioning,
            kind: config.kind,
            startTLS: config.startTLS,
            syncIntervalSecs: config.syncIntervalSecs,
            trustAnchorsPEM: config.trustAnchorsPEM,
            url: config.url,
            userAttributeMap: config.userAttributeMap,
            userFilter: config.userFilter)
    }
}

// MARK: - §31 scim_targets

extension ScimTargetAuth {
    /// `{"type": "bearer"}` — a static bearer token, sent as `Authorization: Bearer <token>`
    /// to the target's `base_url`. The token itself travels as ``ScimTargetInput/credential``,
    /// never here (§31.2: no variant has a member for the credential).
    public static func bearer() -> ScimTargetAuth {
        ScimTargetAuth(type: "bearer", raw: .object(["type": .string("bearer")]))
    }

    /// `{"type": "oauth2_client_credentials", "token_url", "client_id", "scope"?}` — AXIAM
    /// obtains an access token from `tokenURL`. The client secret travels as
    /// ``ScimTargetInput/credential``, never here.
    public static func oauth2ClientCredentials(
        tokenURL: String,
        clientID: String,
        scope: String? = nil
    ) -> ScimTargetAuth {
        var members: [String: ManagementJSON] = [
            "type": .string("oauth2_client_credentials"),
            "token_url": .string(tokenURL),
            "client_id": .string(clientID),
        ]
        if let scope { members["scope"] = .string(scope) }
        return ScimTargetAuth(type: "oauth2_client_credentials", raw: .object(members))
    }
}

extension ScimTargetScope {
    /// `{"type": "all_users"}` — every user of the tenant.
    public static func allUsers() -> ScimTargetScope {
        ScimTargetScope(type: "all_users", raw: .object(["type": .string("all_users")]))
    }

    /// `{"type": "groups", "group_ids": […]}` — users who are direct members of any listed
    /// group (1 – 100 groups of the tenant).
    public static func groups(_ groupIDs: [String]) -> ScimTargetScope {
        ScimTargetScope(
            type: "groups",
            raw: .object([
                "type": .string("groups"),
                "group_ids": .array(groupIDs.map { ManagementJSON.string($0) }),
            ]))
    }
}

extension ScimTargetInput {
    /// The read-modify-write form for `scim_targets.update`, a **replacement**: a read result
    /// turned back into the body, every member carried over.
    ///
    /// `credential` is left `nil` — absent keeps the stored one, unless the write moves its URL
    /// or changes `auth.type` (§31.3 rule 2). No response carries the credential, and this SDK
    /// holds none.
    public init(copying target: ScimTargetResponse) {
        self.init(
            auth: target.auth,
            baseURL: target.baseURL,
            credential: nil,
            deprovision: target.deprovision,
            enabled: target.enabled,
            name: target.name,
            pushGroups: target.pushGroups,
            scope: target.scope,
            userNameFrom: target.userNameFrom)
    }
}

// MARK: - §32 ssf

extension SsfStreamInput {
    /// The read-modify-write form for `ssf.update_stream`, a **replacement**: a read result
    /// turned back into the body, every member carried over.
    ///
    /// `authorizationHeader` is left `nil` — absent keeps the stored header (§32.2), unless the
    /// update moves `endpointURL` to another origin (§32.3 rule 5) — and so is
    /// `clearAuthorizationHeader`. No response carries the header.
    public init(copying stream: SsfStream) {
        self.init(
            audience: stream.audience,
            authorizationHeader: nil,
            clearAuthorizationHeader: nil,
            deliveryMethod: stream.deliveryMethod,
            description: stream.description,
            endpointURL: stream.endpointURL,
            eventsAllowed: stream.eventsAllowed,
            eventsRequested: stream.eventsRequested,
            receiverClientID: stream.receiverClientID,
            status: stream.status,
            statusReason: stream.statusReason,
            subjectFormat: stream.subjectFormat)
    }
}
