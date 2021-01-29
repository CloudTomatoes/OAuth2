<?php

namespace CloudTomatoes\OAuth2\Service;

use CloudTomatoes\OAuth2\Domain\Model\Provider;
use CloudTomatoes\OAuth2\Domain\Repository\ProviderRepository;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Doctrine\PersistenceManager;

/**
 * Class ProviderService
 * @package CloudTomatoes\OAuth2\Service
 * @Flow\Scope("singleton")
 */
class ProviderService
{
    /**
     * @var ProviderRepository
     * @Flow\Inject
     */
    protected $repository;

    /**
     * @var PersistenceManager
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @param Provider $provider
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function create(Provider $provider): void
    {
        $this->repository->add($provider);
        $this->persistenceManager->persistAll();
    }

    /**
     * @param Provider $provider
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function remove(Provider $provider): void
    {
        $this->repository->remove($provider);
        $this->persistenceManager->persistAll();
    }

    /**
     * @param string $name
     * @return Provider|null
     */
    public function findByName(string $name): ?Provider
    {
        return $this->repository->findOneByName($name);
    }
}
