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
    ///
    /// `expectedUpdatedAt` is the read's `updatedAt` (contract 1.60, §31.3 rule 4): if another
    /// administrator writes the target in between, the update is `409` and changes nothing —
    /// reload, then retry. Set it to `nil` to replace whatever is stored.
    public init(copying target: ScimTargetResponse) {
        self.init(
            auth: target.auth,
            baseURL: target.baseURL,
            credential: nil,
            deprovision: target.deprovision,
            enabled: target.enabled,
            expectedUpdatedAt: target.updatedAt,
            name: target.name,
            pushGroups: target.pushGroups,
            scope: target.scope,
            userNameFrom: target.userNameFrom)
    }
}

// MARK: - §32 ssf

extension SsfStreamInput {
    /// The **plain converter** for `ssf.update_stream`, a **replacement**: a read result turned
    /// back into the body, every member carried over, for the caller to edit.
    ///
    /// `authorizationHeader` is left `nil` — absent keeps the stored header (§32.2), unless the
    /// update moves `endpointURL` to another origin (§32.3 rule 5) — and so is
    /// `clearAuthorizationHeader`. No response carries the header.
    ///
    /// Contract 1.61 (§32.2): `expectedUpdatedAt` is the read's `updatedAt`, verbatim — the
    /// server's own string, which this SDK's models keep as a `String` rather than a parsed date,
    /// so nothing is rendered again — and a write that landed since (the receiver's pause or
    /// narrowing included) makes the update `409` (`ConflictError`, never retried) instead of
    /// being reverted; reload, then retry. `eventsRequested` is the one the read carried and is
    /// never dropped: an empty array stays `[]` (the receiver's "none").
    ///
    /// **The caller's duty (contract 1.62, §32.2).** This converter cannot know that you are about
    /// to lower `eventsAllowed`, so **cutting `eventsRequested` to the new `eventsAllowed` is
    /// yours, wherever you build the body this way**: a requested list left outside the new
    /// ceiling is refused `400`, and one left out altogether *resets* the stream to every event of
    /// `eventsAllowed` (the three meanings of `eventsRequested`: absent resets, `[]` is none, a
    /// list is stored as given). An update conditional on the version you read is `409` once the
    /// stream changes under it. ``changing(_:_:)`` does the cut for you and is the form to use
    /// when you edit a stream.
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
            expectedUpdatedAt: stream.updatedAt,
            receiverClientID: stream.receiverClientID,
            status: stream.status,
            statusReason: stream.statusReason,
            subjectFormat: stream.subjectFormat)
    }

    /// The **change-taking read-modify-write form** for `ssf.update_stream` (contract 1.62,
    /// CONTRACT.md §32.2): `(stream, changes) → body`. Hand it the stream you read and a closure
    /// that edits the copy; it returns the replacement body.
    ///
    /// ```swift
    /// let stream = try await client.ssf.getStream(streamID: id)
    /// let body = SsfStreamInput.changing(stream) { $0.eventsAllowed = [.sessionRevoked] }
    /// _ = try await client.ssf.updateStream(streamID: id, body: body)
    /// ```
    ///
    /// What the body carries, and why each point is a rule rather than a convenience:
    ///
    /// - **`eventsRequested`, as read.** An update that omits it *resets* the stream to every
    ///   event of `eventsAllowed`, widening what the receiver narrowed, and AXIAM then sends the
    ///   receiver more events about the tenant's users than it asked for. The read list goes back
    ///   as it was; an `[]` (the receiver's "none") goes back as `[]` and is never omitted.
    /// - **Cut to the new ceiling.** When `changes` lowers `eventsAllowed` and does not name
    ///   `eventsRequested`, the requested list becomes the entries of the read list that are in
    ///   the new `eventsAllowed`, in their order (a request outside the ceiling is `400`). An
    ///   `eventsRequested` that `changes` sets to anything other than what was read — a list, `[]`
    ///   or `nil` (absent: a reset) — is sent as given: the server judges it. Setting it to the
    ///   very value that was read is the same as not naming it, and is cut like the rest. This
    ///   differs from §32.2 read literally, which would send a value set to the one read as
    ///   given (the server then answering `400` if it lies outside the new ceiling): here the
    ///   cut is applied instead, which is benign. To send the read list uncut, build the body
    ///   with ``init(copying:)`` and edit it yourself.
    /// - **`expectedUpdatedAt`, as read.** The `updatedAt` string of the stream you read, byte for
    ///   byte — never parsed and rendered again, because the comparison is of the instant and a
    ///   timestamp rounded to fewer fraction digits than the server stored does not match. The
    ///   update then lands only on the version you read, and a write made since (the receiver's
    ///   own included) answers `409` (`ConflictError`, never retried): read again and decide
    ///   again. Setting it to `nil` in `changes` is "none": the key is left out of the body and
    ///   `null` is never sent, which replaces whatever is stored.
    /// - **The header.** `authorizationHeader` and `clearAuthorizationHeader` start `nil`
    ///   (absent keeps the stored header, §32.2); set them in `changes` when the update moves
    ///   `endpointURL` to another origin (§32.3 rule 5).
    ///
    /// ``init(copying:)`` is the plain converter, and the cut is the caller's duty there.
    public static func changing(
        _ stream: SsfStream,
        _ changes: (inout SsfStreamInput) throws -> Void
    ) rethrows -> SsfStreamInput {
        var body = SsfStreamInput(copying: stream)
        let asRead: [SsfEventType]? = stream.eventsRequested
        try changes(&body)
        if body.eventsRequested == asRead {
            // Not named by the caller: carry the read list, cut to the ceiling the body now has.
            let ceiling = Set(body.eventsAllowed)
            body.eventsRequested = stream.eventsRequested.filter { ceiling.contains($0) }
        }
        return body
    }
}
