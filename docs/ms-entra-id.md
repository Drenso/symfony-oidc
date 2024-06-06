# Microsoft Entra ID

While Microsoft Entra ID supports OpenID Connect, it is by default inconsistent with the tokens that are being generated. This is because Entra ID uses two tokens versions, and even when the V2 token endpoint is used it will return a V1 access token.

### Identify

You can identify this issue using xdebug (break on the `verifyTokens` method call in the `OidcJwtHelper` class) to inspect the access token contents. If it contains the claim `ver` with value `1`, you are getting the wrong access token version. You can use the following statement when paused in that method:

```php
self::parseToken($tokens->getTokenByType(OidcTokenType::ACCESS))->claims()->get('ver')
```

### Solutions

Luckily, with some simple configuration you can solve this issue.

#### Option 1: Fully configure V2 tokens

1. According to the [Microsoft documentation](https://learn.microsoft.com/en-gb/entra/identity-platform/reference-app-manifest?WT.mc_id=Portal-Microsoft_AAD_RegisteredApps#accesstokenacceptedversion-attribute), you can set the `accessTokenAcceptedVersion` to `2` in the app manifest. It might take some time to propagate.
2. If that doesn't work, you can configure a custom scope. See [this comment](https://github.com/Drenso/symfony-oidc/issues/62#issuecomment-2151759001) for some more details on how that can look. Make sure to add your custom scope to your `generateAuthorizationRedirect` call, so Entra ID is forced to generate a V2 token.

#### Option 2: Use V1 tokens

> This is not the recommended solution, only use this if option 1 doesn't work for you!

You can fully revert to the V1 tokens. This can be achieved by removing `/v2.0` from the well-known URL.

### Future

According to Microsoft: 

> Starting August 2024, new Microsoft Entra applications created using any interface (including the Microsoft Entra admin center, Azure portal, Powershell/CLI, or the Microsoft Graph application API) will have the default value of the 'requestedAccessTokenVersion' property in the app registration set to '2'; this is a change from the previous default of 'null' (meaning '1'). This means that new resource applications receive v2 access tokens instead of v1 by default. This improves the security of apps.

This might solve the issue completely for new applications.

### References

- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#v10-and-v20-tokens
- https://learn.microsoft.com/en-gb/entra/identity-platform/reference-app-manifest?WT.mc_id=Portal-Microsoft_AAD_RegisteredApps#accesstokenacceptedversion-attribute
- https://stackoverflow.com/questions/59790209/access-token-issuer-from-azure-ad-is-sts-windows-net-instead-of-login-microsofto
- https://stackoverflow.com/questions/66693477/wrong-version-of-access-token-expect-v2-received-v1
