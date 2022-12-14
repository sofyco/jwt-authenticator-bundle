<?php declare(strict_types=1);

namespace Sofyco\Bundle\JwtAuthenticatorBundle\Security\Encoder;

use Lcobucci\JWT;

final class JwtEncoder
{
    private const IDENTIFIER_KEY = 'id';

    public function __construct(private readonly JWT\Configuration $configuration, private readonly string $ttl)
    {
    }

    public function encode(string $id): string
    {
        return $this->configuration
            ->builder()
            ->issuedAt(new \DateTimeImmutable())
            ->expiresAt(new \DateTimeImmutable($this->ttl))
            ->withClaim(self::IDENTIFIER_KEY, $id)
            ->getToken($this->configuration->signer(), $this->configuration->signingKey())
            ->toString();
    }

    public function decode(string $jwt): string
    {
        $token = $this->configuration->parser()->parse($jwt);

        if (!$token instanceof JWT\UnencryptedToken) {
            throw new Exception\UnexpectedTokenException();
        }

        if ($token->isExpired(new \DateTime())) {
            throw new Exception\TokenExpiredException();
        }

        $id = $token->claims()->get(self::IDENTIFIER_KEY);

        if (\is_string($id)) {
            return $id;
        }

        throw new Exception\UnexpectedIdentifierException();
    }
}
