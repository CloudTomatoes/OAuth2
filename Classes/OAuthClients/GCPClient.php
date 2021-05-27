<?php

namespace CloudTomatoes\OAuth2\OAuthClients;

use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\OAuthClientException;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\Google;
use Neos\Cache\Exception;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\UriInterface;
use CloudTomatoes\OAuth2\Domain\Model\Provider;

/**
 * Class GCPClient
 * @package CloudTomatoes\OAuth2\OAuthClients
 * @Flow\Scope("singleton")
 */
class GCPClient extends AbstractClient
{
    /**
     * Returns the service type, i.e. a specific implementation of this client to use
     *
     * @return string For example, "FlownativeBeach", "oidc", ...
     */
    public function getServiceType(): string
    {
        return Provider::OAUTH_CLIENTS[GCPClient::class];
    }
    /**
     * @param string $clientId
     * @param string $clientSecret
     * @return Google
     */
    protected function createOAuthProvider(string $clientId, string $clientSecret): GenericProvider
    {
        return new Google([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $this->renderFinishAuthorizationUri(),
            'urlAuthorize' => $this->getAuthorizeTokenUri(),
            'urlAccessToken' => $this->getAccessTokenUri(),
            'urlResourceOwnerDetails' => $this->getResourceOwnerUri(),
            'accessType' => 'offline'
        ], [
            'requestFactory' => $this->getRequestFactory()
        ]);
    }

    /**
     * Start OAuth authorization with the Authorization Code flow
     * @see This is overriden from the default client to make sure the scope is passed as an array
     *
     * @param string $clientId The client id, as provided by the OAuth server
     * @param string $clientSecret The client secret, provided by the OAuth server
     * @param UriInterface $returnToUri URI to return to when authorization is finished
     * @param string $scope Scope to request for authorization. Must be scope ids separated by space, e.g. "openid profile email"
     * @return UriInterface The URL the browser should redirect to, asking the user to authorize
     * @throws OAuthClientException
     */
    public function startAuthorization(string $clientId, string $clientSecret, UriInterface $returnToUri, string $scope): UriInterface
    {
        $authorization = new Authorization($this->getServiceType(), $clientId, Authorization::GRANT_AUTHORIZATION_CODE, $scope);
        $this->logger->info(sprintf('OAuth (%s): Starting authorization %s using client id "%s", a %s bytes long secret and scope "%s".', $this->getServiceType(), $authorization->getAuthorizationId(), $clientId, strlen($clientSecret), $scope));

        try {
            $oldAuthorization = $this->entityManager->find(Authorization::class, $authorization->getAuthorizationId());
            if ($oldAuthorization !== null) {
                $authorization = $oldAuthorization;
            }
            $authorization->setClientSecret($clientSecret);
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (ORMException $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed storing authorization in database: %s', $this->getServiceType(), $exception->getMessage()), 1568727133);
        }

        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);
        $authorizationUri = new Uri($oAuthProvider->getAuthorizationUrl(['scope' => explode(' ', $scope)]));

        if ($clientId === $clientSecret) {
            $this->logger->error(sprintf('OAuth (%s): Client ID and Client secret are the same! Please check your configuration.', $this->getServiceType()));
        }

        try {
            $this->stateCache->set(
                $oAuthProvider->getState(),
                [
                    'authorizationId' => $authorization->getAuthorizationId(),
                    'clientId' => $clientId,
                    'clientSecret' => $clientSecret,
                    'returnToUri' => (string)$returnToUri
                ]
            );
        } catch (Exception $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed setting cache entry for authorization: %s', $this->getServiceType(), $exception->getMessage()), 1560178858);
        }

        return $authorizationUri;
    }
}
