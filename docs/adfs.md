# Microsoft AD FS

Active Directory Federation Services (ADFS) is Microsoft's on-prem identity solution. Operators run it themselves on
Windows Server.

### Symptom: access token `iss` claim does not match the discovery `issuer`

Error message:

```text
Unable to verify JWT claims - The token violates some mandatory constraints, details:
  - The token was not issued by the given issuers
```

Some ADFS deployments may return access tokens whose `iss` claim does not match the `issuer` field from the discovery
document:

- the **ID token** `iss` matches the discovery `issuer`,
- the **access token** `iss` matches a different value, published in a non-standard `access_token_issuer` field in the
  discovery document (`.well-known/openid-configuration`).

> **Info:** The `access_token_issuer` field is described in Microsoft's [MS-OIDCE][ms-oidce] protocol extension.

#### Solution

Enable `allow_discovery_access_token_issuer` on the affected client:

```yaml
drenso_oidc:
  clients:
    default:
      well_known_url: '%env(OIDC_WELL_KNOWN_URL)%'
      client_id: '%env(OIDC_CLIENT_ID)%'
      client_secret: '%env(OIDC_CLIENT_SECRET)%'
      allow_discovery_access_token_issuer: true
```

When enabled, the bundle reads `access_token_issuer` from the discovery document and uses it as the expected issuer when
validating the access token. It falls back to the standard `issuer` when the field is absent, so enabling it does not
break clients whose discovery doc does not publish it.

#### Why is this opt-in?

`access_token_issuer` is a vendor extension, not part of the OIDC Discovery 1.0 spec. By deliberately requiring
an explicit opt-in before acting on it, the validation behaviour of any given deployment does not silently change
if its IdP starts publishing the field (whether by intent, misconfiguration, or compromise).

### References

- [MS-OIDCE: OpenID Connect 1.0 Protocol Extensions][ms-oidce] - describes `access_token_issuer`
- [OpenID Connect Discovery 1.0][oidc-discovery]
- [Issue #106][issue-106]

[ms-oidce]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oidce/f629647a-4825-465b-80bb-32c7e9cec2c8
[oidc-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[issue-106]: https://github.com/Drenso/symfony-oidc/issues/106
