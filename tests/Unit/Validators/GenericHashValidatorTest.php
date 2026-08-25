<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Validators;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SecretPlacement;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Validators\AbstractHashValidator;
use Cofa\PaymentValidator\Validators\AbstractSignatureValidator;
use Cofa\PaymentValidator\Validators\GenericHashValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The plain-hash counterpart to `GenericHmacValidator`: a gateway that folds
 * the key into the message must be a configuration entry, not a fork.
 */
#[CoversClass(GenericHashValidator::class)]
#[CoversClass(AbstractHashValidator::class)]
#[CoversClass(AbstractSignatureValidator::class)]
#[CoversClass(SecretPlacement::class)]
final class GenericHashValidatorTest extends TestCase
{
    private const SECRET = 'plain-hash-gateway-secret';

    #[Test]
    public function it_validates_a_key_appended_digest(): void
    {
        $validator = GenericHashValidator::forFields(
            gateway: 'acmepay',
            secret: self::SECRET,
            fields: ['ref', 'amount', 'status'],
            signatureField: 'checksum',
        );

        $data = ['ref' => 'R-1', 'amount' => '10.00', 'status' => 'PAID'];
        $data['checksum'] = hash('sha256', 'R-110.00PAID' . self::SECRET);

        $result = $validator->validate(Payload::fromArray($data));

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('acmepay', $result->gateway());
        self::assertSame(SecretPlacement::Append, $validator->secretPlacement());
    }

    #[Test]
    public function it_validates_a_key_prepended_digest(): void
    {
        // The shape of Fawry's legacy V1 notification, which the package does
        // not ship but must not make impossible to support.
        $validator = GenericHashValidator::forFields(
            gateway: 'legacy',
            secret: self::SECRET,
            fields: ['amount', 'ref', 'status'],
            signatureField: 'messageSignature',
            algorithm: 'md5',
            secretPlacement: SecretPlacement::Prepend,
        );

        $data = ['amount' => '10.00', 'ref' => 'R-1', 'status' => 'PAID'];
        $data['messageSignature'] = md5(self::SECRET . '10.00R-1PAID');

        self::assertTrue($validator->validate(Payload::fromArray($data))->isValid());
    }

    #[Test]
    public function the_two_placements_do_not_accept_each_others_digests(): void
    {
        $data = ['ref' => 'R-1'];

        $appended = GenericHashValidator::forFields('a', self::SECRET, ['ref']);
        $prepended = GenericHashValidator::forFields(
            gateway: 'p',
            secret: self::SECRET,
            fields: ['ref'],
            secretPlacement: SecretPlacement::Prepend,
        );

        $withAppendedDigest = Payload::fromArray($data + ['signature' => hash('sha256', 'R-1' . self::SECRET)]);

        self::assertTrue($appended->validate($withAppendedDigest)->isValid());
        self::assertTrue($prepended->validate($withAppendedDigest)->isInvalid());
    }

    #[Test]
    public function a_plain_hash_is_not_interchangeable_with_an_hmac(): void
    {
        $validator = GenericHashValidator::forFields('acmepay', self::SECRET, ['ref']);

        $payload = Payload::fromArray([
            'ref' => 'R-1',
            'signature' => hash_hmac('sha256', 'R-1', self::SECRET),
        ]);

        self::assertTrue($validator->validate($payload)->isInvalid());
    }

    #[Test]
    public function the_signing_string_stops_short_of_the_secret(): void
    {
        $validator = GenericHashValidator::forFields('acmepay', self::SECRET, ['ref', 'amount']);
        $payload = Payload::fromArray(['ref' => 'R-1', 'amount' => '10.00']);

        self::assertSame('R-110.00', $validator->signingString($payload));
        self::assertStringNotContainsString(self::SECRET, $validator->signingString($payload));
        self::assertSame(hash('sha256', 'R-110.00' . self::SECRET), $validator->sign($payload));
    }

    #[Test]
    public function it_accepts_a_custom_serializer_and_signature_location(): void
    {
        $validator = new GenericHashValidator(
            gateway: 'acmepay',
            secret: self::SECRET,
            serializer: new ConcatenatedFieldSerializer(['ref', 'amount'], ':'),
            signatureLocation: SignatureLocation::header('X-Checksum', stripPrefix: 'sha256='),
        );

        $payload = Payload::fromArray(
            ['ref' => 'R-1', 'amount' => '10.00'],
            ['X-Checksum' => 'sha256=' . hash('sha256', 'R-1:10.00' . self::SECRET)],
        );

        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function it_reports_missing_signed_fields_on_a_mismatch(): void
    {
        $validator = GenericHashValidator::forFields('acmepay', self::SECRET, ['ref', 'amount']);
        $result = $validator->validate(Payload::fromArray(['ref' => 'R-1', 'signature' => 'wrong']));

        self::assertTrue($result->isInvalid());
        self::assertSame(['amount'], $result->contextValue('missing_fields'));
    }

    #[Test]
    public function it_accepts_algorithms_hmac_does_not_offer(): void
    {
        // hash_algos() is a superset of hash_hmac_algos(); a hash validator must
        // be checked against the right list or legacy gateways become impossible.
        self::assertContains('crc32b', hash_algos());
        self::assertNotContains('crc32b', hash_hmac_algos());

        $validator = GenericHashValidator::forFields('acmepay', self::SECRET, ['ref'], algorithm: 'crc32b');
        $payload = Payload::fromArray(['ref' => 'R-1', 'signature' => hash('crc32b', 'R-1' . self::SECRET)]);

        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function it_rejects_an_algorithm_this_system_does_not_have(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('not available on this system');

        GenericHashValidator::forFields('acmepay', self::SECRET, ['ref'], algorithm: 'sha3-999');
    }

    #[Test]
    public function it_refuses_to_be_built_without_a_secret(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('non-empty secret');

        GenericHashValidator::forFields('acmepay', '  ', ['ref']);
    }
}
