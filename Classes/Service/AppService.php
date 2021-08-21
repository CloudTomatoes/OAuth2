<?php

namespace CloudTomatoes\OAuth2\Service;

use Azure\Module\Exception\NoRegisteredProviderFoundException;
use CloudTomatoes\OAuth2\Domain\Model\App;
use CloudTomatoes\OAuth2\Domain\Repository\AppRepository;
use CloudTomatoes\OAuth2\OAuthClients\AbstractClient;
use Flownative\OAuth2\Client\OAuthClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Neos\Flow\Persistence\Doctrine\PersistenceManager;

/**
 * Class AppService
 * @package CloudTomatoes\OAuth2\Service
 */
class AppService
{
    /**
     * @Flow\Inject
     * @var AppRepository
     */
    protected $appRepository;

    /**
     * @var PersistenceManager
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @var UriBuilder
     * @Flow\Inject
     */
    protected $uriBuilder;

    /**
     * @var AuthorizationService
     * @Flow\Inject
     */
    protected $authorizationService;

    /**
     * @param App $app
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function create(App $app): void
    {
        $this->appRepository->add($app);
        $this->persistenceManager->persistAll();
    }

    /**
     * @param App $app
     * @throws \Neos\Flow\Persistence\Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function update(App $app): void
    {
        $this->appRepository->update($app);
        $this->persistenceManager->persistAll();
    }

    /**
     * @param App $app
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function remove(App $app): void
    {
        $this->authorizationService->deleteAuthorization($app->getAuthorizationId());
        $this->appRepository->remove($app);
        $this->persistenceManager->persistAll();
    }

    /**
     * @param string $identifier
     * @return App|null
     */
    public function findByIdentifier(string $identifier): ?App
    {
        return $this->appRepository->findByIdentifier($identifier);
    }

    /**
     * @param string $name
     * @return App|null
     */
    public function findByName(string $name): ?App
    {
        return $this->appRepository->findOneByName($name);
    }

    /**
     * @param App $app
     * @param ActionRequest $request
     * @return string The redirect uri
     * @throws \Flownative\OAuth2\Client\OAuthClientException
     */
    public function authorize(App $app, ActionRequest $request, $controllerName = 'App', $packageKey = 'CloudTomatoes.OAuth2'): string
    {
        $clientClass = $app->getProvider()->getOauthClient();
        /** @var OAuthClient $client */
        $client = new $clientClass($app);
        $uri = new UriBuilder();
        $uri->setRequest($request);
        $returnUri = new Uri($uri->setCreateAbsoluteUri(true)->uriFor('finishAuthorization', ['app' => $app], $controllerName, $packageKey, null));
        if ($clientClass === 'CloudTomatoes\OAuth2\OAuthClients\AzureClient') {
            return $client->startAuthorization($app->getClientId(), $app->getSecret(), $returnUri, $app->getScope(), $app->getResource());
        } else {
            return $client->startAuthorization($app->getClientId(), $app->getSecret(), $returnUri, $app->getScope());
        }
    }

    /**
     * @param App $app
     * @param string $authorizationId
     * @return bool
     * @throws \Neos\Flow\Persistence\Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function finishAuthorization(App $app, string $authorizationId)
    {
        $app->setAuthorizationId($authorizationId);
        $this->appRepository->update($app);
        $this->persistenceManager->persistAll();
        return true;
    }

    /**
     * @param App $app
     * @param string $uri
     * @param string $apiVersion
     * @param null $method
     * @param array $body
     * @return false|array
     * @throws \Flownative\OAuth2\Client\OAuthClientException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function sendAuthenticatedRequest(App $app, string $uri, string $apiVersion, $method = null, array $body = [])
    {
        if ($method === '' || $method === null) {
            $method = 'GET';
        }

        $clientClass = $app->getProvider()->getOauthClient();
        /** @var AbstractClient $client */
        $client = new $clientClass($app);
        $authorization = $client->getAuthorization($app->getAuthorizationId());
        $expired = $authorization->getAccessToken()->hasExpired();
        if ($expired) {
            $client->refreshAuthorization($app->getAuthorizationId(), $app->getClientId(), '');
            $expired = false;
        }

        if ($expired === false) {
            try {
                $result = $client->sendAuthenticatedRequest($authorization, sprintf('%s?api-version=%s', $uri, $apiVersion), $method, $body);
                $resultArray = json_decode($result->getBody()->getContents(), true);
                // If multiple nodes, the contents we need is in 'value', in single nodes in root
                return isset($resultArray['value']) ? $resultArray['value'] : $resultArray;
            } catch (ClientException $exception) {
                // @todo provide proper feedback for other errors
                if ($exception->getCode() === 404) {
                    return 'ResourceNotFound';
                } else if ($exception->getCode() === 400) {
                    \Neos\Flow\var_dump([$uri, $apiVersion ], 'code 400');
                    return json_decode($exception->getResponse()->getBody()->getContents(), true);
                } else {
                    $response = $exception->getResponse()->getBody()->getContents();
                    \Neos\Flow\var_dump($exception, $uri); // Leave here temporary until the todo from line 181 is fixed
                }
            }
        }
    }

    /**
     * De-authorize application
     *
     * @param App $app
     * @throws \Neos\Flow\Persistence\Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function disconnect(App $app)
    {
        $this->authorizationService->deleteAuthorization($app->getAuthorizationId());
        $app->setAuthorizationId('');
        $this->appRepository->update($app);
        $this->persistenceManager->persistAll();
    }
}
