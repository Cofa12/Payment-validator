# Payment Validator

Signature and authenticity validation for payment gateway callbacks, in PHP.

Every gateway signs its webhooks differently — different field sets, different
orders, different hashes, and in HyperPay's case no signature at all — but every
integration needs the same answer: *did this really come from the gateway, and
was it altered on the way here?* This package gives that answer through one
interface, with the per-gateway details isolated so a new gateway is usually a
few lines of configuration rather than a new integration.

Ships with **Paymob**, **EasyKash**, **HyperPay** and **Kashier**.

## Requirements

PHP 8.2+ with `ext-hash`, `ext-json` and `ext-openssl`.

## Installation

```bash
composer require appssquare/payment-validator
```

## Quick start

```php
use Appssquare\PaymentValidator\PaymentValidator;
use Appssquare\PaymentValidator\Support\Payload;

$validator = PaymentValidator::fromConfig([
    'paymob'   => ['hmac' => getenv('PAYMOB_HMAC')],
    'kashier'  => ['api_key' => getenv('KASHIER_API_KEY')],
    'easykash' => ['secret' => getenv('EASYKASH_SECRET')],
    'hyperpay' => ['decryption_key' => getenv('HYPERPAY_WEBHOOK_KEY')],
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
`signature_keys` for Kashier, and the decrypted `payload` for HyperPay.

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
use Appssquare\PaymentValidator\Gateways\Paymob\Paymob;

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
use Appssquare\PaymentValidator\Gateways\Kashier\Kashier;

// If your redirect URL carries parameters Kashier never signed, exclude them:
Kashier::validator($apiKey, additionalExcluded: ['lang', 'utm_source']);
```

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
use Appssquare\PaymentValidator\Gateways\EasyKash\EasyKash;

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
use Appssquare\PaymentValidator\Validators\GenericHmacValidator;

$validator->register('fawry', GenericHmacValidator::forFields(
    gateway: 'fawry',
    secret: getenv('FAWRY_SECRET'),
    fields: ['merchantRefNumber', 'orderAmount', 'orderStatus'],
    signatureField: 'messageSignature',
    algorithm: 'sha256',
));
```

### 2. A different signing string

Swap the serializer. Four ship with the package, and they cover most schemes:

| Serializer | Signs |
| --- | --- |
| `ConcatenatedFieldSerializer` | Named fields in order, optional glue, alias and case-insensitive lookup |
| `QueryStringSerializer` | The payload re-encoded as a query string |
| `TemplateSerializer` | A literal formula: `"/?payment={merchantId}.{orderId}.{amount}"` |
| `RawBodySerializer` | The untouched request body |

```php
use Appssquare\PaymentValidator\Serializers\RawBodySerializer;
use Appssquare\PaymentValidator\Support\SignatureLocation;

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
decimal places an amount carries. Implement `ValueNormalizer` and pass it to the
serializer:

```php
new ConcatenatedFieldSerializer(['amount', 'paid'], ':', $yourNormalizer);
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

Implement `SignatureValidator` directly — three methods. HyperPay does exactly
this.

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

To drive a new gateway from `config/payments.php` like the built-in four, teach
the factory:

```php
use Appssquare\PaymentValidator\GatewayFactory;

$factory = (new GatewayFactory())->extend('fawry', fn (array $config) =>
    GenericHmacValidator::forFields(
        gateway: 'fawry',
        secret: $config['secret'],
        fields: ['merchantRefNumber', 'orderAmount'],
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

Convenient, but it resolves every registered gateway to ask. Route per gateway
when you can.

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
- **Validation is not authorisation.** A valid signature proves origin and
  integrity, nothing else. Still check the amount, currency and status against
  your own order, and make the handler idempotent — gateways retry, and a
  replayed callback carries a perfectly valid signature.

### A note on decimals

Gateways sign the text they sent. If a gateway sends `"amount": 100.00` as a
JSON number, PHP decodes it to `100.0` and re-renders it as `"100"`, which will
not reproduce the signature. Where this bites, either sign the raw body
(`RawBodySerializer`) or supply a `ValueNormalizer` that formats the value the
way the gateway does. None of the four built-in gateways are affected.

## Testing

```bash
composer test
```

```bash
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-text
```

314 unit tests cover the four gateways against signatures computed independently
from each gateway's published recipe — so the tests check the implementation
against the spec, not against itself. Alongside the happy paths they assert that
tampering with any signed field is caught, that a wrong secret is rejected, that
truncated, extended, type-juggled and non-string signatures are refused, and
that no secret reaches a log, a dump or a stack trace.

## Continuous integration

`.github/workflows/ci.yml` runs the suite on every push and pull request against
PHP 8.4. The static-analysis step is present but commented out, ready for when
you add Psalm.

## License

MIT. See [LICENSE](LICENSE).
