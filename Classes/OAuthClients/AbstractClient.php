<?php

namespace CloudTomatoes\OAuth2\OAuthClients;

use CloudTomatoes\OAuth2\Domain\Repository\AppRepository;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use GuzzleHttp\Psr7\Uri;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use CloudTomatoes\OAuth2\Domain\Model\App;
use Neos\Flow\Annotations as Flow;
use CloudTomatoes\OAuth2\Domain\Repository\ProviderRepository;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

abstract class AbstractClient extends OAuthClient
{
    /**
     * @var App
     */
    protected $app;

    /**
     * @Flow\Inject()
     * @var ObjectManagerInterface
     */
    protected $objectManager;

    /**
     * AbstractClient constructor.
     * @param $app
     */
    public function __construct($app)
    {
        if ($app instanceof App) {
            $this->app = $app;
        } elseif (is_string($app)) {
            $appRepository = new AppRepository();
            $this->app = $appRepository->findOneByName($app);
        }
        $serviceName = $this->app ? $this->app->getName() : $app;
        parent::__construct($serviceName);
    }

    /**
     * Returns the OAuth server's base URI
     *
     * @return string For example https://myservice.flownative.com
     */
    public function getBaseUri(): string
    {
        return $this->app->getApiUri();
    }

    /**
     * Returns the OAuth service endpoint for authorizing a token.
     * Override this method if needed.
     *
     * @return string
     */
    public function getAuthorizeTokenUri(): string
    {
        if ($this->app) {
            $provider = $this->app->getProvider();
        } else {
            $providerRepository = $this->objectManager->get(ProviderRepository::class);
            $provider = $providerRepository->findOneByOauthClient('CloudTomatoes\OAuth2\OAuthClients\GCPClient');
        }
        return trim($provider->getAuthenticationEndpoint(), '/') . '/authorize';
    }

    /**
     * Returns the OAuth service endpoint for the access token.
     * Override this method if needed.
     *
     * @return string
     */
    public function getAccessTokenUri(): string
    {
        if ($this->app) {
            $provider = $this->app->getProvider();
        } else {
            $providerRepository = $this->objectManager->get(ProviderRepository::class);
            $provider = $providerRepository->findOneByOauthClient('CloudTomatoes\OAuth2\OAuthClients\AzureClient');
        }
        return trim($provider->getAuthenticationEndpoint(), '/') . '/token';
    }

    /**
     * Returns the OAuth service endpoint for accessing the resource owner details.
     * Override this method if needed.
     *
     * @return string
     */
    public function getResourceOwnerUri(): string
    {
        if ($this->app) {
            $provider = $this->app->getProvider();
        } else {
            $providerRepository = $this->objectManager->get(ProviderRepository::class);
            $provider = $providerRepository->findOneByOauthClient('CloudTomatoes\OAuth2\OAuthClients\AzureClient');
        }
        return trim($provider->getAuthenticationEndpoint(), '/') . '/token/resource';
    }

    /**
     * Returns the current client id (for sending authenticated requests)
     *
     * @return string The client id which is known by the OAuth server
     */
    public function getClientId(): string
    {
        return $this->app->getClientId();
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->app->getSecret();
    }

    /**
     * Finish an OAuth authorization with the Authorization Code flow
     *
     * @param string $stateIdentifier The state identifier, passed back by the OAuth server as the "state" parameter
     * @param string $code The authorization code given by the OAuth server
     * @param string $scope The scope granted by the OAuth server
     * @return UriInterface The URI to return to
     * @throws OAuthClientException
     */
    public function finishAuthorization(string $stateIdentifier, string $code, string $scope): UriInterface
    {
        $stateFromCache = $this->stateCache->get($stateIdentifier);
        if (empty($stateFromCache)) {
            throw new OAuthClientException(sprintf('OAuth: Finishing authorization failed because oAuth state %s could not be retrieved from the state cache.', $stateIdentifier), 1558956494);
        }

        $authorizationId = $stateFromCache['authorizationId'];
        $clientId = $stateFromCache['clientId'];
        $clientSecret = $stateFromCache['clientSecret'];
        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);

        $this->logger->info(sprintf('OAuth (%s): Finishing authorization for client "%s", authorization id "%s", using state %s.', $this->getServiceType(), $clientId, $authorizationId, $stateIdentifier));
        try {
            $authorization = $this->entityManager->find(Authorization::class, $authorizationId);

            if (!$authorization instanceof Authorization) {
                throw new OAuthClientException(sprintf('OAuth2 (%s): Finishing authorization failed because authorization %s could not be retrieved from the database.', $this->getServiceType(), $authorizationId), 1568710771);
            }

            $this->logger->debug(sprintf('OAuth (%s): Retrieving an OAuth access token for authorization "%s" in exchange for the code %s', $this->getServiceType(), $authorizationId, str_repeat('*', strlen($code) - 3) . substr($code, -3, 3)));
            $accessToken = $oAuthProvider->getAccessToken(Authorization::GRANT_AUTHORIZATION_CODE, ['code' => $code]);

            $this->logger->info(sprintf('OAuth (%s): Persisting OAuth token for authorization "%s" with expiry time %s.', $this->getServiceType(), $authorizationId, $accessToken->getExpires()));

            $authorization->setAccessToken($accessToken);

            $accessTokenValues = $accessToken->getValues();
            $scope = $accessTokenValues['scope'] ?? $scope;
            $authorization->setScope($scope);
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage() . ' ' . $exception->getResponseBody()['error_description'], 1511187001671, $exception);
        }

        $returnToUri = new Uri($stateFromCache['returnToUri']);
        $returnToUri = $returnToUri->withQuery(trim($returnToUri->getQuery() . '&' . self::AUTHORIZATION_ID_QUERY_PARAMETER_NAME_PREFIX . '=' . $authorizationId, '&'));

        $this->logger->debug(sprintf('OAuth (%s): Finished authorization "%s", $returnToUri is %s.', $this->getServiceType(), $authorizationId, $returnToUri));
        return $returnToUri;
    }

    /**
     * Returns a prepared request to an OAuth 2.0 service provider using Bearer token authentication
     *
     * @param Authorization $authorization
     * @param string $relativeUri A relative URI of the web server, prepended by the base URI
     * @param string $method The HTTP method, for example "GET" or "POST"
     * @param array $bodyFields Associative array of body fields to send (optional)
     * @return RequestInterface
     * @throws OAuthClientException
     */
    public function getAuthenticatedRequest(Authorization $authorization, string $relativeUri, string $method = 'GET', array $bodyFields = []): RequestInterface
    {
        $accessToken = $authorization->getAccessToken();
        if ($accessToken === null) {
            throw new OAuthClientException(sprintf($this->getServiceType() . 'Failed getting an authenticated request for client ID "%s" because the authorization contained no access token', $authorization->getClientId()), 1589300319);
        }
        $oAuthProvider = $this->createOAuthProvider($authorization->getClientId(), $this->getSecret());
        return $oAuthProvider->getAuthenticatedRequest(
            $method,
            $this->getBaseUri() . $relativeUri,
            $authorization->getAccessToken(),
            [
                'headers' => [
                    'Content-Type' => 'application/json'
                ],
                'body' => ($bodyFields !== [] ? \GuzzleHttp\json_encode($bodyFields) : '')
            ]
        );
    }

    /**
     * Refresh an OAuth authorization
     *
     * @param string $authorizationId
     * @param string $clientId
     * @param string $returnToUri
     * @return string
     * @throws OAuthClientException
     */
    public function refreshAuthorization(string $authorizationId, string $clientId, string $returnToUri): string
    {
        $authorization = $this->entityManager->find(Authorization::class, ['authorizationId' => $authorizationId]);
        if (!$authorization instanceof Authorization) {
            throw new OAuthClientException(sprintf('OAuth2: Could not refresh OAuth token because authorization %s was not found in our database.', $authorization), 1505317044316);
        }
        $oAuthProvider = $this->createOAuthProvider($clientId, $this->getSecret());
        $this->logger->info(sprintf('OAuth (%s): Refreshing authorization %s for client "%s" using a %s bytes long secret and refresh token "%s".', $this->getServiceType(), $authorizationId, $clientId, strlen($this->getSecret()), $authorization->getAccessToken()->getRefreshToken()));

        try {
            $accessToken = $oAuthProvider->getAccessToken('refresh_token', ['refresh_token' => $authorization->getAccessToken()->getRefreshToken()]);
            $authorization->setAccessToken($accessToken);
            $authorization->setExpires($accessToken->getExpires() ? \DateTimeImmutable::createFromFormat('U', $accessToken->getExpires()) : null);
            $this->logger->debug(sprintf($this->getServiceType() . ': New access token is "%s", refresh token is "%s".', $authorization->getAccessToken()->getToken(), $authorization->getAccessToken()->getRefreshToken()));

            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (IdentityProviderException $exception) {
            throw new OAuthClientException($exception->getMessage(), 1511187196454, $exception);
        }

        return $returnToUri;
    }
}
