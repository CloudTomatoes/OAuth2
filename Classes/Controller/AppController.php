<?php

namespace Refactory\OAuth\Controller;

/*
 * This file is part of the Refactory.OAuth package.
 */

use Flownative\OAuth2\Client\Authorization;
use Flownative\OAuth2\Client\OAuthClient;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\Exception\StopActionException;
use Refactory\OAuth\Domain\Model\App;
use Refactory\OAuth\Domain\Repository\ProviderRepository;
use Refactory\OAuth\OAuthClients\GCPClient;
use Refactory\OAuth\Service\AuthorizationService;

class AppController extends AbstractController
{

    /**
     * @Flow\Inject
     * @var \Refactory\OAuth\Domain\Repository\AppRepository
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
    public function showAction(App $app, $queryResult = null, string $uri = null, string $method = null)
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

    /**
     * @param App $newApp
     * @return void
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

    /**
     * @param App $app
     * @return void
     */
    public function updateAction(App $app)
    {
        $this->appRepository->update($app);
        $this->addFlashMessage('Updated the app.');
        $this->redirect('index');
    }

    /**
     * @param App $app
     * @throws StopActionException
     * @throws \Neos\Flow\Http\Exception
     * @throws \Neos\Flow\Mvc\Routing\Exception\MissingActionNameException
     */
    public function authorizeAction(App $app)
    {
        // If we get here and already have an authorization instance for this app, redirect to the app page
        if ($app->getAuthorizationId()) {
            $this->redirect('show', null, null, ['app' => $app]);
        }

        $clientClass = $app->getProvider()->getOauthClient();
        /** @var OAuthClient $client */
        $client = new $clientClass($app);
        $returnUri = new Uri($this->uriBuilder->setCreateAbsoluteUri(true)->uriFor('finishAuthorization', ['app' => $app], 'App', 'Refactory.OAuth', null));
        $this->redirectToUri($client->startAuthorization($app->getClientId(), $app->getSecret(), $returnUri, $app->getScope()));
    }

    /**
     * @param App $app
     * @throws \Neos\Flow\Mvc\Exception\NoSuchArgumentException
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function finishAuthorizationAction(App $app)
    {
        $authorizationId = $this->request->getArgument('flownative_oauth2_authorization_id');
        if (!$authorizationId) {
            $this->addFlashMessage('Something went wrong in the authentication part.');
        }
        $app->setAuthorizationId($authorizationId);
        $this->appRepository->update($app);
        $this->persistenceManager->persistAll();
        $this->redirect('show', null, null, ['app' => $app]);
    }

    /**
     * @Flow\IgnoreValidation("$app")
     * @param App $app
     * @return void
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
     * @throws \Flownative\OAuth2\Client\OAuthClientException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function sendAuthenticatedRequestAction(App $app, string $uri, string $method = 'GET', array $body = [])
    {
        if ($method === '') $method = 'GET';

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
            $result = $client->sendAuthenticatedRequest($authorization, $uri, $method, $body);
            $this->redirect('show', null, null, [
                'app' => $app,
                'queryResult' => $result->getBody()->getContents(),
                'uri' => $uri,
                'method' => $method
            ]);
        }
    }

    /**
     * @param App $app
     * @throws \Flownative\OAuth2\Client\OAuthClientException
     * @throws \Neos\Flow\Http\Exception
     * @throws \Neos\Flow\Mvc\Routing\Exception\MissingActionNameException
     */
    public function refreshAuthorizationAction(App $app)
    {
        $clientClass = $app->getProvider()->getOauthClient();
        /** @var GCPClient $client */
        $client = new $clientClass($app);
        $this->redirectToUri($client->refreshAuthorization($app->getAuthorizationId(), $app->getClientId(), $this->uriBuilder->uriFor('show', ['app' => $app])));
    }
}
