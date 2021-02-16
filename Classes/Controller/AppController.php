<?php

namespace CloudTomatoes\OAuth2\Controller;

/*
 * This file is part of the CloudTomatoes.OAuth2 package.
 */

use CloudTomatoes\OAuth2\Service\AppService;
use Flownative\OAuth2\Client\OAuthClient;
use Flownative\OAuth2\Client\OAuthClientException;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Exception;
use Neos\Flow\Mvc\Exception\NoSuchArgumentException;
use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException;
use Neos\Flow\Mvc\Routing\Exception\MissingActionNameException;
use Neos\Flow\Persistence\Exception\IllegalObjectTypeException;
use CloudTomatoes\OAuth2\Domain\Model\App;
use CloudTomatoes\OAuth2\Domain\Repository\AppRepository;
use CloudTomatoes\OAuth2\Domain\Repository\ProviderRepository;
use CloudTomatoes\OAuth2\OAuthClients\GCPClient;
use CloudTomatoes\OAuth2\Service\AuthorizationService;

class AppController extends AbstractController
{

    /**
     * @Flow\Inject
     * @var AppRepository
     */
    protected $appRepository;

    /**
     * @Flow\Inject()
     * @var ProviderRepository
     */
    protected $providerRepository;

    /**
     * @Flow\Inject()
     * @var AuthorizationService
     */
    protected $authorizationService;

    /**
     * @var AppService
     * @Flow\Inject
     */
    protected $appService;

    /**
     * @return void
     */
    public function indexAction()
    {
        $this->view->assign('apps', $this->appRepository->findAll());
    }

    /**
     * @Flow\IgnoreValidation("$app")
     * @param App $app
     * @param string|null $queryResult
     * @param string|null $uri
     * @param string|null $method
     * @return void
     */
    public function showAction(App $app, $queryResult = null, $uri = null, $method = null)
    {
        $clientClass = $app->getProvider()->getOauthClient();
        /** @var OAuthClient $client */
        $client = new $clientClass($app);

        $this->view->assign('app', $app);
        $this->view->assign('queryResult', $queryResult);
        $this->view->assignMultiple([
            'uri' => $uri,
            'method' => $method
        ]);
        $this->view->assign('redirectUri', $client->renderFinishAuthorizationUri());
    }

    /**
     * @return void
     */
    public function newAction()
    {
        $this->view->assign('providers', $this->providerRepository->findAll());
    }

    protected function initializeCreateAction()
    {
        $this->arguments['newApp']->getPropertyMappingConfiguration()->allowProperties('provider');
    }

    /**
     * @param App $newApp
     * @return void
     * @throws StopActionException
     * @throws IllegalObjectTypeException
     */
    public function createAction(App $newApp)
    {
        $this->appRepository->add($newApp);
        $this->addFlashMessage('Created a new app.');
        $this->redirect('index');
    }

    /**
     * @Flow\IgnoreValidation("$app")
     * @param App $app
     * @return void
     */
    public function editAction(App $app)
    {
        $this->view->assign('providers', $this->providerRepository->findAll());
        $this->view->assign('app', $app);
    }

    protected function initializeUpdateAction()
    {
        $this->arguments['app']->getPropertyMappingConfiguration()->allowProperties('provider');
    }

    /**
     * @param App $app
     * @return void
     * @throws IllegalObjectTypeException
     * @throws StopActionException
     */
    public function updateAction(App $app)
    {
        $this->appRepository->update($app);
        $this->addFlashMessage('Updated the app.');
        $this->redirect('index');
    }

    /**
     * @param App $app
     * @throws Exception
     * @throws StopActionException
     * @throws OAuthClientException
     * @throws UnsupportedRequestTypeException
     * @throws MissingActionNameException
     */
    public function authorizeAction(App $app)
    {
        // If we get here and already have an authorization instance for this app, redirect to the app page
        if ($app->getAuthorizationId()) {
            $this->redirect('show', null, null, ['app' => $app]);
        }

        $redirectUri = $this->appService->authorize($app, $this->request);

        if ($redirectUri) {
            $this->redirectToUri($redirectUri);
        }
    }

    /**
     * @param App $app
     * @throws NoSuchArgumentException
     * @throws IllegalObjectTypeException|StopActionException
     */
    public function finishAuthorizationAction(App $app)
    {
        $authorizationId = $this->request->getArgument('flownative_oauth2_authorization_id');
        if (!$authorizationId) {
            $this->addFlashMessage('Something went wrong in the authentication part.');
        }
        $this->appService->finishAuthorization($app, $authorizationId);
        $this->redirect('show', null, null, ['app' => $app]);
    }

    /**
     * @Flow\IgnoreValidation("$app")
     * @param App $app
     * @return void
     * @throws IllegalObjectTypeException
     * @throws StopActionException
     */
    public function deleteAction(App $app)
    {
        // Clean up the authorization
        $this->addFlashMessage("Deleted the app {$app->getName()}");
        $this->authorizationService->deleteAuthorization($app->getAuthorizationId());
        $this->appRepository->remove($app);
        $this->redirect('index');
    }

    /**
     * @param App $app
     * @throws IllegalObjectTypeException
     * @throws StopActionException
     */
    public function deAuthorizeAction(App $app)
    {
        $this->authorizationService->deleteAuthorization($app->getAuthorizationId());
        $app->setAuthorizationId('');
        $this->appRepository->update($app);
        $this->persistenceManager->persistAll();
        $this->redirect('show', null, null, ['app' => $app]);
    }

    /**
     * @param App $app
     * @param string $uri
     * @param string $method
     * @param array $body
     * @throws StopActionException
     * @throws OAuthClientException
     * @throws GuzzleException
     */
    public function sendAuthenticatedRequestAction(App $app, $uri, $method = null, array $body = [])
    {
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
                $result = $client->sendAuthenticatedRequest($authorization, $uri, $method, $body);
            } catch (ClientException $e) {
                $queryResult = 'Response: ' . $e->getCode() . PHP_EOL . 'Request URI: ' . $e->getRequest()->getUri() . PHP_EOL . 'Result:' . PHP_EOL . json_encode(json_decode($e->getResponse()->getBody()->getContents()), JSON_PRETTY_PRINT);
            }
            $this->redirect('show', null, null, [
                'app' => $app,
                'queryResult' => isset($queryResult) ? $queryResult : json_encode(json_decode($result->getBody()->getContents()), JSON_PRETTY_PRINT),
                'uri' => $uri,
                'method' => $method
            ]);
        }
    }

    /**
     * @param App $app
     * @throws Exception
     * @throws MissingActionNameException
     * @throws OAuthClientException
     * @throws StopActionException
     * @throws UnsupportedRequestTypeException
     */
    public function refreshAuthorizationAction(App $app)
    {
        $clientClass = $app->getProvider()->getOauthClient();
        /** @var GCPClient $client */
        $client = new $clientClass($app);
        $this->redirectToUri($client->refreshAuthorization($app->getAuthorizationId(), $app->getClientId(), $this->uriBuilder->uriFor('show', ['app' => $app])));
    }
}
