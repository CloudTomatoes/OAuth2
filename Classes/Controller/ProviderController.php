<?php
namespace CloudTomatoes\OAuth2\Controller;

/*
 * This file is part of the CloudTomatoes.OAuth2 package.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use CloudTomatoes\OAuth2\Domain\Model\Provider;
use CloudTomatoes\OAuth2\Domain\Repository\ProviderRepository;

class ProviderController extends AbstractController
{

    /**
     * @Flow\Inject
     * @var ProviderRepository
     */
    protected $providerRepository;

    /**
     * @return void
     */
    public function indexAction()
    {
        $this->view->assign('providers', $this->providerRepository->findAll());
    }

    /**
     * @Flow\IgnoreValidation("$provider")
     * @param Provider $provider
     * @return void
     */
    public function showAction(Provider $provider)
    {
        $this->view->assign('provider', $provider);
    }

    /**
     * @return void
     */
    public function newAction()
    {
        $this->view->assign('oauthClients', Provider::OAUTH_CLIENTS);
    }

    /**
     * @param Provider $newProvider
     * @return void
     */
    public function createAction(Provider $newProvider)
    {
        $this->providerRepository->add($newProvider);
        $this->addFlashMessage('Created a new provider.');
        $this->redirect('index');
    }

    /**
     * @Flow\IgnoreValidation("$provider")
     * @param Provider $provider
     * @return void
     */
    public function editAction(Provider $provider)
    {
        $this->view->assign('oauthClients', Provider::OAUTH_CLIENTS);
        $this->view->assign('provider', $provider);
    }

    /**
     * @param Provider $provider
     * @return void
     */
    public function updateAction(Provider $provider)
    {
        $this->providerRepository->update($provider);
        $this->addFlashMessage('Updated the provider.');
        $this->redirect('index');
    }

    /**
     * @Flow\IgnoreValidation("$provider")
     * @param Provider $provider
     * @return void
     */
    public function deleteAction(Provider $provider)
    {
        $this->providerRepository->remove($provider);
        $this->addFlashMessage('Deleted a provider.');
        $this->redirect('index');
    }
}
