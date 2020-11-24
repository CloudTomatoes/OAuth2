<?php
namespace CloudTomatoes\OAuth2\Service;

use Doctrine\ORM\EntityManagerInterface;
use Flownative\OAuth2\Client\Authorization;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;

/**
 * Class AuthorizationService
 * @package CloudTomatoes\OAuth2\Service
 */
class AuthorizationService
{
    /**
     * @Flow\Inject
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @Flow\Inject()
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * Removes the app-related authorization from the database
     * @param $authorizationId
     */
    public function deleteAuthorization($authorizationId)
    {
        $authorization = $this->entityManager->find(Authorization::class, $authorizationId);
        if ($authorization instanceof Authorization) {
            $this->entityManager->remove($authorization);
            $this->persistenceManager->persistAll();
        }
    }

    /**
     * @param $authorizationId
     * @return Authorization
     */
    public function getAuthorizationById($authorizationId)
    {
        /** @var Authorization $authorization */
        $authorization = $this->entityManager->find(Authorization::class, $authorizationId);
        return $authorization;
    }
}
