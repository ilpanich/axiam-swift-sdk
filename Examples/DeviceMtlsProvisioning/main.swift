// DeviceMtlsProvisioning — provision an IoT device, then let it authenticate.
//
// This is the flow the certificate namespaces exist for, end to end, and it is two
// programs' worth of work in one file so the seam between them is visible:
//
//   PART 1 (operator side, §27): create a service account for the device, generate a device
//   certificate signed by the tenant's signing CA, and bind the certificate to the account
//   so the server will accept it as that identity.
//
//   PART 2 (device side, §6.1): a second client configured with that certificate as its
//   mTLS client identity. Every request it makes presents the certificate; the TLS handshake
//   IS the credential, so there is no password and no client secret on that side.
//
// THE ONE-TIME SECRET (§27.5) is the whole reason these are two parts.
// `GeneratedCertificate.privateKeyPEM` is returned exactly once, by exactly this call, and
// the server does not store it. If the operator side does not write it somewhere the device
// can read, nobody can ever recover it and the only fix is to generate a new certificate.
// `Sensitive<T>` is what keeps it from being lost the OTHER way: it renders as
// `[SENSITIVE]` in every stringification sink — every interpolation, every log line — so
// the way to get the bytes out is to ask for them, at the one point of use, with
// `.expose()`. It still reaches the wire; it just does not reach your log aggregator by
// accident.
//
// Set AXIAM_PROVISION=1 to run part 1 (it writes). Part 2 runs whenever
// AXIAM_DEVICE_CERT / AXIAM_DEVICE_KEY name readable PEM files.
//
// Build:  swift build --target DeviceMtlsProvisioningExample
// Run:    swift run DeviceMtlsProvisioningExample

import Foundation
import AxiamSDK

func env(_ key: String, default fallback: String) -> String {
    ProcessInfo.processInfo.environment[key] ?? fallback
}

let baseURLString = env("AXIAM_BASE_URL", default: "https://localhost:8443")
guard let baseURL = URL(string: baseURLString) else {
    fatalError("Invalid AXIAM_BASE_URL: \(baseURLString)")
}

let tenantID = env("AXIAM_TENANT_ID", default: "11111111-1111-1111-1111-111111111111")
let orgID = env("AXIAM_ORG_ID", default: "11111111-1111-1111-1111-111111111111")
let serial = env("AXIAM_DEVICE_SERIAL", default: "device-0001")
let certPath = env("AXIAM_DEVICE_CERT", default: "\(serial).crt.pem")
let keyPath = env("AXIAM_DEVICE_KEY", default: "\(serial).key.pem")

// ---- PART 1: the operator provisions the device ------------------------

func provision() async throws {
    let config = try AxiamConfig(baseURL: baseURL, tenantID: tenantID, orgID: orgID)
    let client = try AxiamClient(config: config)
    _ = try await client.login(
        email: env("AXIAM_EMAIL", default: "admin@example.com"),
        password: env("AXIAM_PASSWORD", default: "changeme"))

    // 1. The identity the device will authenticate AS.
    //
    // A device is a machine, so it gets a service account rather than a user. The response
    // carries a `clientSecret` — a one-time secret this flow does not need, because the
    // device will present a certificate instead. It is wrapped in `Sensitive` all the same:
    // "we are not going to use it" is not a reason to let it print.
    let account = try await client.serviceAccounts.create(
        body: CreateServiceAccountRequest(
            description: "IoT device \(serial)", name: serial))
    print("""
        service account \(account.id) (client_id \(account.clientID))
          client_secret: \(account.clientSecret)  <- redacted by §7
        """)

    // 2. The signing CA to issue from.
    //
    // Per-tenant signing CAs are chained beneath the ORGANIZATION's CA, which is why this is
    // addressed under the organization's `caCertificates` handle with the tenant named
    // explicitly rather than implied.
    let signingCAs = try await client.caCertificates.listSigningCas(tenantID: tenantID)
    guard let ca = signingCAs.items.first else {
        print("""
            tenant \(tenantID) has no signing CA — generate one first with
            client.caCertificates.generateSigningCA(...).
            """)
        exit(1)
    }
    print("signing CA \(ca.id) (\(ca.subject))")

    // 3. The certificate itself.
    //
    // Ed25519 rather than RSA-4096 because the thing holding the private key is a
    // microcontroller; both are permitted and this is the one that will not dominate its
    // boot time.
    let issued = try await client.certificates.generate(body: CreateCertificateRequest(
        certType: .device,
        issuerCAID: ca.id,
        keyAlgorithm: .ed25519,
        metadata: .object(["serial": .string(serial)]),
        subject: "CN=\(serial)",
        validityDays: 365))

    print("""
        certificate \(issued.id)
          subject     \(issued.subject)
          fingerprint \(issued.fingerprint)
          valid       \(issued.notBefore) .. \(issued.notAfter)
          private_key \(issued.privateKeyPEM)  <- redacted by §7
        """)

    // THE ONE MOMENT the private key exists outside the device. `.expose()` is deliberately
    // awkward to reach and deliberately narrow in scope: the revealed value is used on the
    // next line and nowhere else.
    //
    // Writing it with the narrowest permissions the platform offers is the caller's job;
    // this example writes plainly and says so, because pretending otherwise would be worse
    // than being explicit about what it does not do.
    try Data(issued.publicCertPEM.utf8).write(to: URL(fileURLWithPath: certPath))
    try Data(issued.privateKeyPEM.expose().utf8).write(to: URL(fileURLWithPath: keyPath))
    print("wrote \(certPath) and \(keyPath) — the key is unrecoverable if these are lost")

    // 4. Bind the certificate to the account.
    //
    // Until this lands, the certificate is a valid certificate that authenticates as nobody:
    // the server has no mapping from its fingerprint to an identity. This is the step whose
    // absence looks like "mTLS is broken" when it is actually "mTLS worked and the identity
    // was unknown".
    try await client.serviceAccounts.bindCertificate(
        saID: account.id, body: BindCertificate(certificateID: issued.id))
    print("bound certificate \(issued.id) to account \(account.id)")

    // 5. The listener must trust the CA for CLIENT certificates.
    //
    // Separate from the CA existing and separate from it having signed this certificate: a
    // CA AXIAM issues from is not automatically a CA it will accept client certificates
    // from, because those are different trust decisions. `restartRequired` comes back true
    // because rustls builds its client trust store once, when the listener is constructed.
    if env("AXIAM_SET_TRUST_ANCHOR", default: "") == "1" {
        let anchored = try await client.caCertificates.setMtlsTrustAnchor(
            id: ca.id, body: SetMtlsTrustAnchor(enabled: true))
        print(anchored.message
              + (anchored.restartRequired ? "  (takes effect at next start)" : ""))
    }
}

// ---- PART 2: the device authenticates ----------------------------------

func authenticateAsDevice() async throws {
    let certURL = URL(fileURLWithPath: certPath)
    let keyURL = URL(fileURLWithPath: keyPath)
    guard FileManager.default.fileExists(atPath: certURL.path),
          FileManager.default.fileExists(atPath: keyURL.path) else {
        print("\n(set AXIAM_DEVICE_CERT and AXIAM_DEVICE_KEY to run the device half)")
        return
    }

    // A SECOND client. The operator's client above holds an administrator's session; this
    // one holds a device's certificate and nothing else, and the two must not be the same
    // object — a device that inherited the operator's session would act as the operator.
    //
    // §6.1: the key never leaves this process and is never sent. TLS proves possession of it
    // without transmitting it, and presenting a client certificate never relaxes server
    // verification (§6.1 rule 2). The key is wrapped in `Sensitive` from the moment it is
    // read, so it cannot reach a log through the config either.
    let deviceConfig = try AxiamConfig(
        baseURL: baseURL,
        tenantID: tenantID,
        orgID: orgID,
        clientCertificate: .pem(
            certificate: try Data(contentsOf: certURL),
            privateKey: try Data(contentsOf: keyURL)))
    let device = try AxiamClient(config: deviceConfig)

    // Every request this client makes now presents the certificate, and the server reads the
    // device's identity off the one the TLS handshake already validated. There is no
    // password, no client secret and no username in the call below — the credential IS the
    // connection.
    let decision = try await device.checkAccess(
        "read", resource: env("AXIAM_RESOURCE_ID", default: "telemetry"))
    print("""

        device authorized as itself over mTLS:
          can read telemetry: \(decision.allowed ? "yes" : "no")
        """)
    if let reason = decision.reasonCode {
        print("  reason: \(reason)")
    }
}

// ------------------------------------------------------------------------

do {
    if env("AXIAM_PROVISION", default: "") == "1" {
        try await provision()
    } else {
        print("(set AXIAM_PROVISION=1 to run the operator half — it writes)")
    }
    try await authenticateAsDevice()
} catch AxiamError.authz(let error) where error.managementFailure == .conflict {
    // 409 — most likely this serial is already provisioned. Under `.authz`, per §27.4 rule 7.
    print("already provisioned? \(error.message)")
    exit(1)
} catch AxiamError.authz(let error) where error.managementFailure == .notFound {
    // 404 — or the object belongs to another tenant. AXIAM answers the same status for both
    // on purpose, so the SDK does not pretend to tell them apart.
    print("not found (or not yours): \(error.message)")
    exit(1)
} catch {
    print("failed: \(error)")
    exit(1)
}
