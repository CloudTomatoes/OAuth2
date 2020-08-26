<?php
namespace Refactory\OAuth\Controller;

/*
 * This file is part of the Refactory.OAuth package.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Refactory\OAuth\Domain\Model\Provider;
use Refactory\OAuth\Domain\Repository\ProviderRepository;

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
