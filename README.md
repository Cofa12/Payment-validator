# Payment Validator

Signature and authenticity validation for payment gateway callbacks, in PHP.

Every gateway signs its webhooks differently — different field sets, different
orders, different hashes, and in HyperPay's case no signature at all — but every
integration needs the same answer: *did this really come from the gateway, and
was it altered on the way here?* This package gives that answer through one
interface, with the per-gateway details isolated so a new gateway is usually a
few lines of configuration rather than a new integration.

Ships with **Paymob**, **Kashier**, **Fawry**, **PayTabs**, **PayPal**, **HyperPay**
and **EasyKash** — HMAC, plain-hash, RSA and AEAD schemes alike.

## Requirements

PHP 8.2+ with `ext-hash`, `ext-json` and `ext-openssl`.

## Installation

```bash
composer require cofa/payment-validator
```

## Quick start

```php
use Cofa\PaymentValidator\PaymentValidator;
use Cofa\PaymentValidator\Support\Payload;

$validator = PaymentValidator::fromConfig([
    'paymob'   => ['hmac' => getenv('PAYMOB_HMAC')],
    'kashier'  => ['api_key' => getenv('KASHIER_API_KEY')],
    'easykash' => ['secret' => getenv('EASYKASH_SECRET')],
    'hyperpay' => ['decryption_key' => getenv('HYPERPAY_WEBHOOK_KEY')],
    'fawry'    => ['secure_key' => getenv('FAWRY_SECURE_KEY')],
    'paytabs'  => ['server_key' => getenv('PAYTABS_SERVER_KEY')],
    'paypal'   => ['webhook_id' => getenv('PAYPAL_WEBHOOK_ID')],
]);

$result = $validator->validate(
    'paymob',
    Payload::fromJson($rawRequestBody, $requestHeaders),
);

if ($result->isInvalid()) {
    // Log $result->reason(), then reject the request.
    http_response_code(400);
    exit;
}
```

Every gateway is registered lazily, so a secret you never use is never read and
a misconfigured gateway only raises when that gateway is actually called.

### Prefer exceptions?

```php
$validator->assertValid('paymob', $payload);   // throws SignatureMismatchException
```

### Just want a boolean?

```php
if (! $validator->isValid('kashier', $payload)) { … }
```

## Building the payload

A callback reaches you as a body, a set of headers, or a query string, and the
right constructor matters — some gateways sign the raw bytes, and some sign the
query parameters in the order they sent them.

| Constructor | Use for |
| --- | --- |
| `Payload::fromJson($body, $headers)` | JSON webhooks. Keeps the raw body intact. |
| `Payload::fromRawBody($body, $headers)` | Any raw body, JSON or not (HyperPay's hex ciphertext). |
| `Payload::fromQueryString($query, $headers)` | Browser redirects / response callbacks. |
| `Payload::fromArray($data, $headers)` | An already-decoded array. |

```php
// Laravel
$payload = Payload::fromJson($request->getContent(), $request->headers->all());

// A redirect back from the gateway — pass the raw query string, not $_GET,
// so parameter order is preserved.
$payload = Payload::fromQueryString($request->getQueryString());

// Plain PHP
$payload = Payload::fromRawBody(file_get_contents('php://input'), getallheaders());
```

## Reading the result

`ValidationResult` never carries the expected signature or the secret, because
results get logged.

```php
$result->isValid();            // bool
$result->isInvalid();          // bool
$result->gateway();            // 'paymob'
$result->reason();             // null when valid, a sentence when not
$result->context();            // non-secret diagnostics
$result->contextValue('channel');
$result->throwIfInvalid();     // fluent guard
$result->toArray();            // safe to log as-is
```

`context()` is where the useful debugging lives: `missing_fields` when a signed
field never arrived, `channel` for the callback type that matched,
`signature_keys` for Kashier, `cert_url` for PayPal, and the decrypted `payload`
for HyperPay.

## The gateways

### Paymob — HMAC-SHA512

Twenty fields concatenated in lexicographical order with no separator, hashed
with the **HMAC** value from *Dashboard → Settings → Account Info* (not the API
key). Two callback channels are covered and routed automatically:

| Channel | Fires on |
| --- | --- |
| `transaction` | `TRANSACTION` processed callbacks and the browser response callback |
| `card_token` | `TOKEN` callbacks, when a card is saved |

Both the POST webhook (fields nested under `obj`) and the GET redirect (fields
flattened, with dots that PHP rewrites to underscores) are recognised from the
same validator.

```php
use Cofa\PaymentValidator\Gateways\Paymob\Paymob;

Paymob::validator($hmacSecret)->validate($payload);
```

### Kashier — HMAC-SHA256

Signed with the **payment API key**. Two channels:

- **`webhook`** — the fields named by `data.signatureKeys`, URL-encoded in that
  order, compared against `data.kashierSignature`. Because the webhook declares
  its own signed field list, Kashier can add fields without breaking you.
- **`redirect`** — every query parameter except `signature` and `mode`,
  re-encoded in the order received.

```php
use Cofa\PaymentValidator\Gateways\Kashier\Kashier;

// If your redirect URL carries parameters Kashier never signed, exclude them:
Kashier::validator($apiKey, additionalExcluded: ['lang', 'utm_source']);
```

### Fawry — SHA-256 with the key appended

Fawry does not HMAC. It concatenates seven fields, appends your **secure key**,
and takes a plain SHA-256 of the result, delivered as `messageSignature`:

```
SHA-256(fawryRefNumber + merchantRefNumber + paymentAmount + orderAmount
        + orderStatus + paymentMethod + paymentRefrenceNumber + secureKey)
```

The V2 server notification and the hosted checkout's `chargeResponse` carry the
same fields, so one validator answers for both — only the `Payload` constructor
differs:

```php
use Cofa\PaymentValidator\Gateways\Fawry\Fawry;

$fawry = Fawry::validator(getenv('FAWRY_SECURE_KEY'));

$fawry->validate(Payload::fromJson($rawBody));                  // server notification
$fawry->validate(Payload::fromQueryString($request->getQueryString()));   // return URL
```

Two details cause almost every mismatch, and both are handled for you:

- **The amounts are two-decimal text.** Fawry signs `250.00`; PHP decodes the
  JSON number `250.00` to `250.0` and renders it back as `"250"`. A
  `DecimalAmountNormalizer` puts the decimals back before hashing.
- **`paymentRefrenceNumber` is spelled that way by Fawry**, and is absent on
  order-creation notifications, where it signs as empty. Both spellings are
  accepted, as are `merchantRefNum` and `merchantRefNumber`.

> **V1 notifications are deliberately not shipped.** They are
> `md5(secureKey + …)` — a broken digest, and the key placement that invites a
> length-extension attack. If your account is still on V1, wire it up
> explicitly so the choice is visible in your code rather than hidden in a
> dependency:
>
> ```php
> use Cofa\PaymentValidator\Support\SecretPlacement;
> use Cofa\PaymentValidator\Validators\GenericHashValidator;
>
> $validator->register('fawry', GenericHashValidator::forFields(
>     gateway: 'fawry',
>     secret: getenv('FAWRY_SECURE_KEY'),
>     fields: ['amount', 'fawryRefNumber', 'merchantRefNumber', 'orderStatus'],
>     signatureField: 'messageSignature',
>     algorithm: 'md5',
>     secretPlacement: SecretPlacement::Prepend,
> ));
> ```
>
> Then ask Fawry to move you to V2.

### PayTabs — HMAC-SHA256

Signed with the profile **Server Key** (not the Client Key). The two channels
sign quite different things, and are routed automatically:

- **`callback`** — the server-to-server IPN. HMAC over the *entire raw body*,
  with the result in a `signature` header. The body must reach the validator
  byte for byte, so use `Payload::fromJson($request->getContent(), $headers)`;
  a decoded-and-re-encoded array will not reproduce the digest.
- **`return`** — the browser form POST. PayTabs drops `signature`, drops falsy
  values, sorts the rest by key, URL-encodes and hashes that.

```php
use Cofa\PaymentValidator\Gateways\PayTabs\PayTabs;

PayTabs::validator(getenv('PAYTABS_SERVER_KEY'));

// If your return URL carries parameters PayTabs never signed:
PayTabs::validator($serverKey, additionalExcluded: ['lang', 'utm_source']);
```

The "drop falsy values" step is PayTabs' own `array_filter()`, which removes
`""`, `0` **and the string `"0"`**. Surprising as a general rule, but it is the
rule the gateway signs by, so the package reproduces it rather than improving
on it.

### PayPal — RSA-SHA256, verified locally

PayPal signs asymmetrically: there is no shared secret, only a public
certificate to check against. What it signs is four pipe-joined parts —

```
PAYPAL-TRANSMISSION-ID | PAYPAL-TRANSMISSION-TIME | webhookId | crc32(rawBody)
```

— with `PAYPAL-TRANSMISSION-SIG` holding the RSA-SHA256 signature over that
string, under the certificate named by `PAYPAL-CERT-URL`.

```php
use Cofa\PaymentValidator\Gateways\PayPal\PayPal;

PayPal::validator(getenv('PAYPAL_WEBHOOK_ID'));
```

The `webhookId` is the subscription ID from the developer dashboard, and it must
be the one for *this* endpoint — it is inside the signed message, so a webhook
minted for another subscription cannot be replayed against yours. It is an
identifier rather than a secret.

Verifying here rather than calling PayPal's `verify-webhook-signature` endpoint
is what PayPal itself recommends: no extra round trip on the webhook path, no
API credentials needed to check a signature, and no outage in your handler when
that endpoint is slow.

Two things to know:

- **The raw body must survive intact**, because the checksum is `crc32()` over
  the exact bytes PayPal sent. Decoding and re-encoding the JSON changes how
  slashes and numbers are rendered, and verification fails on a webhook that was
  never tampered with.
- **The certificate URL is untrusted input** — it arrives inside the very
  request you are verifying. It is resolved through a `CertificateResolver`
  that refuses any host outside an allow-list (`paypal.com` and its subdomains,
  covering sandbox), rejects non-HTTPS URLs, and does not follow redirects. See
  [Security notes](#security-notes) for why that check carries the whole scheme.

Supply your own resolver to add caching, use your HTTP client, or pin the
certificate so the webhook path makes no outbound request at all:

```php
use Cofa\PaymentValidator\Support\RemoteCertificateResolver;

PayPal::validator($webhookId, new RemoteCertificateResolver(
    allowedHosts: ['paypal.com'],
    fetcher: fn (string $url): ?string => $cache->remember($url, 86400,
        fn () => $httpClient->get($url)->body()),
));
```

Anything implementing `CertificateResolver` works; returning `null` means "do
not trust this request".

PayPal's legacy **IPN** is not covered. It is not a signature scheme — you post
the message back to PayPal and wait for `VERIFIED` — so it needs an HTTP round
trip against PayPal rather than a local check. Use PayPal's own IPN listener
guidance for that, or move the integration to REST webhooks.

### HyperPay — AES-256-GCM

HyperPay does not sign its webhooks; it encrypts them. The body is hex
ciphertext, with the nonce and authentication tag in `X-Initialization-Vector`
and `X-Authentication-Tag`. GCM authenticates as it decrypts, so a body that
opens cleanly under your key provably came from HyperPay unmodified — the same
guarantee an HMAC gives, reached a different way.

The decrypted notification comes back on the result, so you do not decrypt twice:

```php
$result = $validator->validate('hyperpay', $rawBody, $headers);

if ($result->isValid()) {
    $notification = $result->contextValue('payload');   // decoded array
}
```

Use the **webhook decryption key** from *Administration → Webhooks*, hex encoded
as HyperPay presents it. 16-, 24- and 32-byte keys all work; the cipher is
chosen from the key length.

### EasyKash — HMAC-SHA256

> **Confirm the signed field list against your own EasyKash documentation.**
> EasyKash issues per-merchant integration contracts, and the signed field set
> differs between Direct Pay versions and product profiles — unlike Paymob or
> Kashier there is no single published list that holds for every merchant. The
> package ships the common Direct Pay v2 set as a default, and expects you to
> override it when yours differs.

```php
use Cofa\PaymentValidator\Gateways\EasyKash\EasyKash;

// Default set: easykashRef, Amount, Currency, PaymentMethod, productCode, status
EasyKash::validator($secret);

// Yours, when it differs — no need to edit the package:
EasyKash::validator($secret, ['easykashRef', 'Amount', 'status']);
```

Or from configuration:

```php
'easykash' => [
    'secret' => getenv('EASYKASH_SECRET'),
    'fields' => ['easykashRef', 'Amount', 'status'],
],
```

Field lookup is case-insensitive here, because EasyKash mixes `Amount` and
`amount` across channels. If your account also presents a static token header,
both checks can be wired together:

```php
'easykash' => [
    'secret' => getenv('EASYKASH_SECRET'),
    'api_key' => getenv('EASYKASH_API_KEY'),
    'api_key_header' => 'X-Api-Key',
],
```

## Adding a gateway

The package is built so that gateway N+1 does not require changing it. Reach for
the lowest-effort level that fits.

### 1. Configuration only

Most gateways are "concatenate these fields, hash, compare":

```php
use Cofa\PaymentValidator\Validators\GenericHmacValidator;

$validator->register('acmepay', GenericHmacValidator::forFields(
    gateway: 'acmepay',
    secret: getenv('ACMEPAY_SECRET'),
    fields: ['merchantRef', 'orderAmount', 'orderStatus'],
    signatureField: 'checksum',
    algorithm: 'sha256',
));
```

If the gateway hashes the key into the message instead of HMACing it — anything
whose docs read `SHA-256(fields… + secretKey)`, as Fawry's does — reach for
`GenericHashValidator`, which takes the same arguments plus where the key goes:

```php
use Cofa\PaymentValidator\Support\SecretPlacement;
use Cofa\PaymentValidator\Validators\GenericHashValidator;

$validator->register('acmepay', GenericHashValidator::forFields(
    gateway: 'acmepay',
    secret: getenv('ACMEPAY_SECRET'),
    fields: ['merchantRef', 'orderAmount'],
    signatureField: 'checksum',
    secretPlacement: SecretPlacement::Append,   // or Prepend
));
```

### 2. A different signing string

Swap the serializer. Four ship with the package, and they cover most schemes:

| Serializer | Signs |
| --- | --- |
| `ConcatenatedFieldSerializer` | Named fields in order, optional glue, alias and case-insensitive lookup |
| `QueryStringSerializer` | The payload re-encoded as a query string, optionally sorted and empties dropped |
| `TemplateSerializer` | A literal formula: `"/?payment={merchantId}.{orderId}.{amount}"` |
| `RawBodySerializer` | The untouched request body |

```php
use Cofa\PaymentValidator\Serializers\RawBodySerializer;
use Cofa\PaymentValidator\Support\SignatureLocation;

$validator->register('some-gateway', new GenericHmacValidator(
    gateway: 'some-gateway',
    secret: $secret,
    serializer: new RawBodySerializer(),
    signatureLocation: SignatureLocation::header('X-Signature', stripPrefix: 'sha256='),
    algorithm: 'sha512',
));
```

`SignatureLocation` covers a body field (`field()`, dot notation allowed), a
header (`header()`, case-insensitive, optional scheme prefix), several places at
once (`firstOf()`), and anything stranger (`custom()`).

### 3. A different value format

Gateways disagree on how values become strings — `true` vs `1` vs `Y`, how many
decimal places an amount carries. Two normalizers ship with the package:

| Normalizer | Does |
| --- | --- |
| `DefaultValueNormalizer` | JSON spellings: `true`/`false`, `null` as empty. `numericBooleans()` switches to `1`/`0` |
| `DecimalAmountNormalizer` | Re-imposes fixed decimals on named money fields, so `250.0` signs as `250.00` |

Both are injected, so a gateway that disagrees needs your own `ValueNormalizer`
rather than a fork:

```php
new ConcatenatedFieldSerializer(['amount', 'paid'], ':', $yourNormalizer);

// Or wrap one: amounts to two decimals, everything else the default way.
new ConcatenatedFieldSerializer(
    fields: ['ref', 'amount'],
    normalizer: new DecimalAmountNormalizer(['amount']),
);
```

### 4. A recipe of your own

Extend `AbstractHmacValidator` and declare what is signed and where the
signature lives. The template — locate, rebuild, hash, compare in constant time
— is inherited:

```php
final class MyGatewayValidator extends AbstractHmacValidator
{
    public function gateway(): string
    {
        return 'my-gateway';
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        // Chosen per payload, so versioned schemes are a branch, not a new class.
        return new ConcatenatedFieldSerializer(['ref', 'total']);
    }

    protected function signatureLocation(): SignatureLocation
    {
        return SignatureLocation::field('checksum');
    }
}
```

### 5. Not an HMAC at all

Implement `SignatureValidator` directly — three methods. HyperPay does this for
AEAD decryption, and PayPal for public-key verification; neither has a signing
string to rebuild, so neither fits the template.

### Several callback types under one name

Wrap the channels in a `CompositeValidator` and the right one is picked per
request, with the match reported as `context('channel')`:

```php
new CompositeValidator('my-gateway', [
    'webhook' => new MyWebhookValidator($secret),
    'redirect' => new MyRedirectValidator($secret),
]);
```

Each channel still verifies its own signature in full, so trying several is not
a weakening.

### Config-driven registration

To drive a new gateway from `config/payments.php` like the built-in ones, teach
the factory:

```php
use Cofa\PaymentValidator\GatewayFactory;

$factory = (new GatewayFactory())->extend('acmepay', fn (array $config) =>
    GenericHmacValidator::forFields(
        gateway: 'acmepay',
        secret: $config['secret'],
        fields: ['merchantRef', 'orderAmount'],
    ));

$validator = PaymentValidator::fromConfig($config, $factory);
```

### Overriding a built-in gateway

If a gateway changes its scheme before this package catches up, replace it in
your application — no fork required:

```php
$validator->register('paymob', new YourFixedPaymobValidator($secret));
```

## One endpoint for every gateway

```php
$gateway = $validator->detect($payload);   // 'paymob' | 'kashier' | … | null

if ($gateway === null || $validator->validate($gateway, $payload)->isInvalid()) {
    abort(400);
}
```

Convenient, but it resolves every registered gateway to ask, and it returns the
first one that *recognises* the payload rather than the one that verifies. Route
per gateway when you can.

That distinction matters where two gateways sign a similarly shaped payload.
Kashier's redirect claims any payload with a `signature` field, so a PayTabs
return would be handed to Kashier and rejected. PayTabs' return channel narrows
itself by also requiring `tranRef` or `cartId`, but the general point stands: a
shared endpoint is a convenience, and per-gateway routes are what you want in
production.

## Security notes

- **Constant-time comparison.** Signatures are compared with `hash_equals()`.
  A `==` comparison would accept `'0e123…' == '0e456…'` as equal; the test suite
  asserts this cannot happen for any gateway.
- **Secrets stay out of dumps.** Keys are wrapped in `Secret`, which holds the
  value in a `WeakMap` outside the object, so `print_r()`, `var_dump()`,
  `var_export()`, `json_encode()` and framework debug pages show `********`
  rather than your webhook key. Constructors are marked `#[\SensitiveParameter]`
  so stack traces stay clean too, and `Secret` refuses to be serialised.
- **Results are safe to log.** `ValidationResult` never carries the expected
  signature or the secret.
- **Untrusted input never throws.** A malformed, hostile or empty payload is an
  invalid result, not an exception. Only configuration errors raise.
- **An unknown gateway name raises** rather than returning "invalid", so a typo
  in configuration cannot masquerade as a rejected payment.
- **A certificate URL from the request is treated as hostile.** PayPal names its
  signing certificate in a header of the message being verified. An attacker who
  could choose that URL would host their own certificate, sign a forged webhook
  with the matching private key, and pass every check — so
  `RemoteCertificateResolver` refuses any host outside its allow-list before a
  connection is opened, requires HTTPS, and does not follow redirects. That last
  point is not decoration: a redirect from an allow-listed host would otherwise
  lead straight back out of the allow-list. It also closes the obvious SSRF —
  without the check, a webhook endpoint is a "fetch any URL for me" service
  aimed at your internal network.
- **Weak-by-design schemes are labelled, not hidden.** Fawry hashes rather than
  HMACs; the package validates that faithfully but says so, and refuses to ship
  the MD5-with-prepended-key V1 variant as a default. `SecretPlacement::Prepend`
  carries the length-extension warning where you will read it.
- **Validation is not authorisation.** A valid signature proves origin and
  integrity, nothing else. Still check the amount, currency and status against
  your own order, and make the handler idempotent — gateways retry, and a
  replayed callback carries a perfectly valid signature.

### A note on decimals

Gateways sign the text they sent. If a gateway sends `"amount": 100.00` as a
JSON number, PHP decodes it to `100.0` and re-renders it as `"100"`, which will
not reproduce the signature.

Fawry is the built-in gateway this bites, and it is handled — a
`DecimalAmountNormalizer` restores the two decimals its recipe specifies. For a
gateway of your own, the same three options apply: sign the raw body
(`RawBodySerializer`), name the money fields
(`new DecimalAmountNormalizer(['amount'])`), or write a `ValueNormalizer` that
formats values exactly the way the gateway does.

## Testing

```bash
composer test
```

```bash
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-text
```

465 unit tests cover the seven gateways against signatures computed
independently from each gateway's published recipe — so the tests check the
implementation against the spec, not against itself. Alongside the happy paths
they assert that tampering with any signed field is caught, that a wrong secret
is rejected, that truncated, extended, type-juggled and non-string signatures are
refused, that PayPal refuses a certificate URL pointed anywhere but PayPal, and
that no secret reaches a log, a dump or a stack trace.

No test touches the network: PayPal's certificates are generated in-process, and
the default HTTPS transport is exercised through a substituted stream wrapper.

## Continuous integration

`.github/workflows/ci.yml` runs the suite on every push and pull request against
PHP 8.4. The static-analysis step is present but commented out, ready for when
you add Psalm.

## License

MIT. See [LICENSE](LICENSE).
