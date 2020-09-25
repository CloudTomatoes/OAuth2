<?php
namespace CloudTomatoes\OAuth2\Service;

use CloudTomatoes\OAuth2\Domain\Model\App;
use CloudTomatoes\OAuth2\Domain\Repository\AppRepository;
use CloudTomatoes\OAuth2\OAuthClients\GCPClient;
use GuzzleHttp\Exception\ClientException;
use Neos\Flow\Annotations as Flow;

class AppService {
    /**
     * @Flow\Inject
     * @var AppRepository
     */
    protected $appRepository;

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
    public function sendAuthenticatedRequest(App $app, string $uri, $apiVersion = '2020-06-01', $method = null, array $body = [])
    {
        if ($method === '' || $method === null) $method = 'GET';

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
                return isset($resultArray['value']) ? $resultArray['value'] : [];
            } catch (ClientException $e) {
                $queryResult = 'Response: ' . $e->getCode() . PHP_EOL . 'Request URI: ' . $e->getRequest()->getUri() . PHP_EOL . 'Result:' . PHP_EOL . json_encode(json_decode($e->getResponse()->getBody()->getContents()), JSON_PRETTY_PRINT);
            }
        }
    }
}
