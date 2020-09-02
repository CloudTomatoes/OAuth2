<?php
namespace CloudTomatoes\OAuth2\OAuthClients;

use Flownative\OAuth2\Client\OAuthClient;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use CloudTomatoes\OAuth2\Domain\Model\App;
use Neos\Flow\Annotations as Flow;
use CloudTomatoes\OAuth2\Domain\Repository\ProviderRepository;

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
        if ($app instanceof App) $this->app = $app;
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
        return trim($provider->getAuthenticationEndpoint(), '/')  . '/token/resource';
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

}
