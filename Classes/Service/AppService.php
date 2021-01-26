<?php

namespace CloudTomatoes\OAuth2\Service;

use CloudTomatoes\OAuth2\Domain\Model\App;
use CloudTomatoes\OAuth2\Domain\Repository\AppRepository;
use CloudTomatoes\OAuth2\OAuthClients\GCPClient;
use GuzzleHttp\Exception\ClientException;
use Neos\Flow\Annotations as Flow;

class AppService
{
    /**
     * @Flow\Inject
     * @var AppRepository
     */
    protected $appRepository;

    /**
     * @var string
     * @Flow\InjectConfiguration(package="CloudTomatoes.OAuth2", path="default.api.version")
     */
    protected $apiVersion;

    public function findByIdentifier(string $identifier): ?App
    {
        return $this->appRepository->findByIdentifier($identifier);
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
    public function sendAuthenticatedRequest(App $app, string $uri, $apiVersion = null, $method = null, array $body = [])
    {
        if ($apiVersion === null) {
            $apiVersion = $this->apiVersion;
        }

        if ($method === '' || $method === null) {
            $method = 'GET';
        }

        $clientClass = $app->getProvider()->getOauthClient();
        /** @var GCPClient $client */
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
                // @todo: improve (too procedural in writing, better response handling)
                // @todo: make allowed versions configurable
                echo 'Initial api version not found, trying the next...' . PHP_EOL;
                $response = $exception->getResponse()->getBody()->getContents();
                preg_match_all('/(2020-08-01|2019-06-01)/', $response, $matches);
                $apiVersionToUse = $this->determineApiVersion($matches, $apiVersion);
                if (!empty($matches)) {
                    return self::sendAuthenticatedRequest($app, $uri, $apiVersionToUse, $method, $body);
                } else {
                    // If no versions found in the response let's give that back so we can add to the list.
                    \Neos\Flow\var_dump($response);
                }
            }
        }
    }

    /**
     * Function to determine which api version to try after failure on the current api-version
     *
     * @param array $matches
     * @param string $currentVersion
     * @return string
     */
    private function determineApiVersion(array $matches, string $currentVersion): string
    {
        $matches = array_values(array_unique($matches[0]));
        $allowedVersions = [];
        for ($i = 0; $i < count($matches); $i++) {
            $allowedVersions[] = $matches[$i];
        }
        if (array_search($currentVersion, $allowedVersions) !== false) {
            $versionToReturn = $allowedVersions[array_search($currentVersion, $allowedVersions) + 1];
        } else {
            $versionToReturn = $allowedVersions[0];
        }
        return $versionToReturn;
    }
}
