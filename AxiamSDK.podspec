Pod::Spec.new do |s|
  s.name             = 'AxiamSDK'
  s.version          = '1.0.0-alpha12'
  s.summary          = 'Official Swift SDK for AXIAM identity & authorization.'
  s.description      = <<-DESC
    AxiamSDK is the Swift client for AXIAM (Access eXtended Identity and Authorization
    Management). It conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS): tenant-scoped
    REST client, cookie-based sessions, CSRF forwarding, single-flight token refresh, strict
    TLS with optional custom CA and client-certificate mutual TLS, EdDSA/Ed25519 JWKS
    verification, and framework-agnostic route-guard / declarative authorization helpers.
  DESC
  s.homepage         = 'https://github.com/ilpanich/axiam-swift-sdk'
  s.license          = { :type => 'Apache-2.0', :file => 'LICENSE' }
  s.author           = { 'AXIAM' => 'noreply@axiam.dev' }
  s.source           = { :git => 'https://github.com/ilpanich/axiam-swift-sdk.git', :tag => "v#{s.version}" }

  s.swift_version    = '5.9'
  s.osx.deployment_target = '13.0'
  s.ios.deployment_target = '16.0'

  s.source_files     = 'Sources/AxiamSDK/**/*.swift'

  s.dependency 'AsyncHTTPClient', '~> 1.21'
  s.dependency 'SwiftNIOSSL', '~> 2.25'
  s.dependency 'swift-crypto', '~> 3.2'
end
