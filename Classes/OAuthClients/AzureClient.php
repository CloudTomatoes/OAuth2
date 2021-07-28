<?php
namespace CloudTomatoes\OAuth2\OAuthClients;

use CloudTomatoes\OAuth2\Domain\Repository\ProviderRepository;
use Doctrine\ORM\ORMException;
use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\OAuthClientException;
use GuzzleHttp\Psr7\Uri;
use Neos\Cache\Exception;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\Exception\MissingActionNameException;
use CloudTomatoes\OAuth2\Domain\Model\Provider;
use Psr\Http\Message\UriInterface;

class AzureClient extends AbstractClient
{
    /**
     * Returns the service type, i.e. a specific implementation of this client to use
     *
     * @return string For example, "FlownativeBeach", "oidc", ...
     */
    public static function getServiceType(): string
    {
        return Provider::OAUTH_CLIENTS[AzureClient::class];
    }

    /**
     * @see Used to enforce https redirect finisher, not needed if we were
     * developing on https
     *
     * @return string
     */
    public function renderFinishAuthorizationUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getHttpRequest();
        } else {
            putenv('FLOW_REWRITEURLS=1');
            $httpRequest = $this->serverRequestFactory->createServerRequest('GET', new Uri($this->flowBaseUriSetting));
        }
        $actionRequest = ActionRequest::fromHttpRequest($httpRequest);

        $this->uriBuilder->reset();
        $this->uriBuilder->setRequest($actionRequest);
        $this->uriBuilder->setCreateAbsoluteUri(true);

        try {
            $uri = $this->uriBuilder->
            reset()->
            setCreateAbsoluteUri(true)->
            uriFor('finishAuthorization', ['serviceType' => $this->getServiceType(), 'serviceName' => $this->getServiceName()], 'OAuth', 'Flownative.OAuth2.Client');
            $uri = stripos($uri, 'http:', 0) === false ? $uri : str_replace('http:', 'https:', $uri);
            return $uri;
        } catch (MissingActionNameException $e) {
            return '';
        }
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
            $provider = $providerRepository->findOneByOauthClient('CloudTomatoes\OAuth2\OAuthClients\AzureClient');
        }
        return trim($provider->getAuthenticationEndpoint(), '/') . '/authorize';
    }

    /**
     * Start OAuth authorization with the Authorization Code flow
     *
     * @param string $clientId The client id, as provided by the OAuth server
     * @param string $clientSecret The client secret, provided by the OAuth server
     * @param UriInterface $returnToUri URI to return to when authorization is finished
     * @param string $scope Scope to request for authorization. Must be scope ids separated by space, e.g. "openid profile email"
     * @param string $resource
     * @return UriInterface The URL the browser should redirect to, asking the user to authorize
     * @throws OAuthClientException
     */
    public function startAuthorization(string $clientId, string $clientSecret, UriInterface $returnToUri, string $scope, string $resource = ''): UriInterface
    {
        $authorizationId = Authorization::generateAuthorizationIdForAuthorizationCodeGrant($this->getServiceType(), $this->getServiceName(), $clientId);
        $authorization = new Authorization($authorizationId, $this->getServiceType(), $clientId, Authorization::GRANT_AUTHORIZATION_CODE, $scope);
        $this->logger->info(sprintf('OAuth (%s): Starting authorization %s using client id "%s", a %s bytes long secret and scope "%s".', $this->getServiceType(), $authorization->getAuthorizationId(), $clientId, strlen($clientSecret), $scope));

        try {
            $oldAuthorization = $this->entityManager->find(Authorization::class, $authorization->getAuthorizationId());
            if ($oldAuthorization !== null) {
                $authorization = $oldAuthorization;
            }
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        } catch (ORMException $exception) {
            throw new OAuthClientException(sprintf('OAuth (%s): Failed storing authorization in database: %s', $this->getServiceType(), $exception->getMessage()), 1568727133);
        }

        $oAuthProvider = $this->createOAuthProvider($clientId, $clientSecret);
        $authorizationUri = new Uri($oAuthProvider->getAuthorizationUrl(['scope' => $scope, 'resource' => $resource]));

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
