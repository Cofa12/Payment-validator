<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator\Tests\Unit;

use Cofa12\PaymentValidator\Contracts\PayloadSerializer;
use Cofa12\PaymentValidator\Contracts\SignatureValidator;
use Cofa12\PaymentValidator\Contracts\ValueNormalizer;
use Cofa12\PaymentValidator\GatewayFactory;
use Cofa12\PaymentValidator\PaymentValidator;
use Cofa12\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa12\PaymentValidator\Serializers\RawBodySerializer;
use Cofa12\PaymentValidator\Serializers\TemplateSerializer;
use Cofa12\PaymentValidator\Support\Payload;
use Cofa12\PaymentValidator\Support\SignatureLocation;
use Cofa12\PaymentValidator\Support\ValidationResult;
use Cofa12\PaymentValidator\Validators\AbstractHmacValidator;
use Cofa12\PaymentValidator\Validators\GenericHmacValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Adding gateway N+1 must not require touching the package.
 *
 * Each test here integrates a gateway the library has never heard of, using a
 * progressively lower-level extension point — configuration, then a serializer,
 * then a subclass, then a validator written from scratch.
 */
#[CoversClass(GenericHmacValidator::class)]
#[CoversClass(AbstractHmacValidator::class)]
#[CoversClass(GatewayFactory::class)]
#[CoversClass(PaymentValidator::class)]
final class ExtensibilityTest extends TestCase
{
    private const SECRET = 'fictional-gateway-secret';

    #[Test]
    public function a_new_hmac_gateway_needs_only_a_field_list(): void
    {
        $validator = GenericHmacValidator::forFields(
            gateway: 'fawry',
            secret: self::SECRET,
            fields: ['merchantRefNumber', 'orderAmount', 'orderStatus'],
            signatureField: 'messageSignature',
        );

        $data = [
            'merchantRefNumber' => 'REF-1',
            'orderAmount' => '250.00',
            'orderStatus' => 'PAID',
        ];
        $data['messageSignature'] = hash_hmac('sha256', 'REF-1250.00PAID', self::SECRET);

        $result = $validator->validate(Payload::fromArray($data));

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('fawry', $result->gateway());
    }

    #[Test]
    public function a_new_gateway_slots_into_the_registry_alongside_the_built_in_ones(): void
    {
        $validator = PaymentValidator::fromConfig([])
            ->register('fawry', GenericHmacValidator::forFields(
                gateway: 'fawry',
                secret: self::SECRET,
                fields: ['ref', 'amount'],
            ));

        $data = ['ref' => 'R1', 'amount' => '10', 'signature' => hash_hmac('sha256', 'R110', self::SECRET)];

        self::assertSame(['fawry'], $validator->gateways());
        self::assertTrue($validator->isValid('fawry', $data));
    }

    #[Test]
    public function the_gateway_factory_can_be_taught_a_new_gateway_for_config_driven_setups(): void
    {
        $factory = (new GatewayFactory())->extend(
            'fawry',
            static fn (array $config): SignatureValidator => GenericHmacValidator::forFields(
                gateway: 'fawry',
                secret: (string) $config['secret'],
                fields: ['ref', 'amount'],
            ),
        );

        $validator = PaymentValidator::fromConfig(['fawry' => ['secret' => self::SECRET]], $factory);

        $data = ['ref' => 'R1', 'amount' => '10', 'signature' => hash_hmac('sha256', 'R110', self::SECRET)];

        self::assertContains('fawry', $factory->supported());
        self::assertTrue($validator->isValid('fawry', $data));
    }

    #[Test]
    public function a_gateway_that_signs_a_formula_uses_the_template_serializer(): void
    {
        $validator = new GenericHmacValidator(
            gateway: 'formula-pay',
            secret: self::SECRET,
            serializer: new TemplateSerializer('/?payment={merchantId}.{orderId}.{amount}.{currency}'),
            signatureLocation: SignatureLocation::field('hash'),
        );

        $signed = '/?payment=MID-99.ORD-1.250.00.EGP';

        $payload = Payload::fromArray([
            'merchantId' => 'MID-99',
            'orderId' => 'ORD-1',
            'amount' => '250.00',
            'currency' => 'EGP',
            'hash' => hash_hmac('sha256', $signed, self::SECRET),
        ]);

        self::assertSame($signed, $validator->signingString($payload));
        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function a_gateway_that_signs_the_raw_body_with_a_prefixed_header_is_configuration_only(): void
    {
        $body = '{"event":"charge.success","data":{"amount":25000}}';

        $validator = new GenericHmacValidator(
            gateway: 'stripe-like',
            secret: self::SECRET,
            serializer: new RawBodySerializer(),
            signatureLocation: SignatureLocation::header('X-Signature', 'sha512='),
            algorithm: 'sha512',
        );

        $payload = Payload::fromJson($body, [
            'X-Signature' => 'sha512=' . hash_hmac('sha512', $body, self::SECRET),
        ]);

        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function a_gateway_with_an_unusual_value_format_supplies_its_own_normalizer(): void
    {
        $normalizer = new class implements ValueNormalizer {
            public function normalize(mixed $value, string $field): string
            {
                // A gateway that signs amounts with two decimal places and
                // booleans as Y/N — neither is the JSON spelling.
                return match (true) {
                    is_bool($value) => $value ? 'Y' : 'N',
                    $field === 'amount' => number_format((float) $value, 2, '.', ''),
                    default => (string) $value,
                };
            }
        };

        $validator = new GenericHmacValidator(
            gateway: 'picky-pay',
            secret: self::SECRET,
            serializer: new ConcatenatedFieldSerializer(['amount', 'paid'], ':', $normalizer),
            signatureLocation: SignatureLocation::field('sig'),
        );

        $payload = Payload::fromArray([
            'amount' => 250,
            'paid' => true,
            'sig' => hash_hmac('sha256', '250.00:Y', self::SECRET),
        ]);

        self::assertSame('250.00:Y', $validator->signingString($payload));
        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function a_subclass_can_pin_its_own_recipe(): void
    {
        $validator = new class(self::SECRET) extends AbstractHmacValidator {
            public function gateway(): string
            {
                return 'subclassed-pay';
            }

            protected function serializer(Payload $payload): PayloadSerializer
            {
                return new ConcatenatedFieldSerializer(['ref', 'total']);
            }

            protected function signatureLocation(): SignatureLocation
            {
                return SignatureLocation::field('checksum');
            }
        };

        $payload = Payload::fromArray([
            'ref' => 'R1',
            'total' => '99',
            'checksum' => hash_hmac('sha512', 'R199', self::SECRET),
        ]);

        self::assertTrue($validator->validate($payload)->isValid());
        self::assertSame('subclassed-pay', $validator->gateway());
    }

    #[Test]
    public function a_serializer_may_depend_on_the_payload_for_versioned_schemes(): void
    {
        // A gateway that changed its signed field set between API versions:
        // the serializer is chosen per request, not per validator.
        $validator = new class(self::SECRET) extends AbstractHmacValidator {
            public function gateway(): string
            {
                return 'versioned-pay';
            }

            protected function serializer(Payload $payload): PayloadSerializer
            {
                return $payload->get('version') === 2
                    ? new ConcatenatedFieldSerializer(['ref', 'amount', 'currency'])
                    : new ConcatenatedFieldSerializer(['ref', 'amount']);
            }

            protected function signatureLocation(): SignatureLocation
            {
                return SignatureLocation::field('sig');
            }
        };

        $v1 = Payload::fromArray([
            'version' => 1,
            'ref' => 'R1',
            'amount' => '10',
            'currency' => 'EGP',
            'sig' => hash_hmac('sha512', 'R110', self::SECRET),
        ]);

        $v2 = Payload::fromArray([
            'version' => 2,
            'ref' => 'R1',
            'amount' => '10',
            'currency' => 'EGP',
            'sig' => hash_hmac('sha512', 'R110EGP', self::SECRET),
        ]);

        self::assertTrue($validator->validate($v1)->isValid());
        self::assertTrue($validator->validate($v2)->isValid());
    }

    #[Test]
    public function a_gateway_that_does_not_use_hmac_at_all_implements_the_interface_directly(): void
    {
        // HyperPay already proves this in production; here is the minimal shape
        // for anything else that authenticates some other way.
        $validator = new class implements SignatureValidator {
            public function gateway(): string
            {
                return 'allow-listed-ip';
            }

            public function supports(Payload $payload): bool
            {
                return $payload->header('X-Forwarded-For') !== null;
            }

            public function validate(Payload $payload): ValidationResult
            {
                return $payload->header('X-Forwarded-For') === '203.0.113.7'
                    ? ValidationResult::valid('allow-listed-ip')
                    : ValidationResult::invalid('allow-listed-ip', 'Source address is not allow-listed.');
            }
        };

        $registry = PaymentValidator::fromConfig([])->register('allow-listed-ip', $validator);

        self::assertTrue($registry->isValid('allow-listed-ip', [], ['X-Forwarded-For' => '203.0.113.7']));
        self::assertFalse($registry->isValid('allow-listed-ip', [], ['X-Forwarded-For' => '198.51.100.1']));
    }

    #[Test]
    public function a_registered_gateway_can_be_replaced_without_touching_the_package(): void
    {
        // Escape hatch: if a gateway changes its scheme before the package
        // catches up, an application can override the built-in validator.
        $validator = PaymentValidator::fromConfig(['paymob' => ['hmac' => 'x']]);

        $validator->register('paymob', GenericHmacValidator::forFields(
            gateway: 'paymob',
            secret: self::SECRET,
            fields: ['brand_new_field'],
            signatureField: 'hmac',
        ));

        $data = [
            'brand_new_field' => 'value',
            'hmac' => hash_hmac('sha256', 'value', self::SECRET),
        ];

        self::assertTrue($validator->isValid('paymob', $data));
    }
}
