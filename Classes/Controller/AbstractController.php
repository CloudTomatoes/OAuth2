<?php
namespace Refactory\OAuth\Controller;

use Neos\Error\Messages\Message;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Error\Messages as Error;
use Neos\Flow\Annotations as Flow;

class AbstractController extends ActionController {
    /**
     * @return Message The flash message or false if no flash message should be set
     */
    protected function getErrorFlashMessage()
    {
        return new Error\Error('An error occurred while submitting the form. Please fix the errors below.', null,);
    }
}
