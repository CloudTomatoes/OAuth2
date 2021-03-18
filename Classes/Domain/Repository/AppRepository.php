<?php

namespace CloudTomatoes\OAuth2\Domain\Repository;

/*
 * This file is part of the CloudTomatoes.OAuth2 package.
 */

use CloudTomatoes\OAuth2\Domain\Model\App;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Repository;

/**
 * @Flow\Scope("singleton")
 */
class AppRepository extends Repository
{
    public function findByIdentifier($identifier): ?App
    {
        return parent::findByIdentifier($identifier);
    }
}
