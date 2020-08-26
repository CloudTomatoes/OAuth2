<?php
namespace Refactory\OAuth\OAuthClients;

use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Http\HttpRequestHandlerInterface;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\Exception\MissingActionNameException;
use Refactory\OAuth\Domain\Model\Provider;

class AzureClient extends AbstractClient
{
    /**
     * Returns the service type, i.e. a specific implementation of this client to use
     *
     * @return string For example, "FlownativeBeach", "oidc", ...
     */
    public function getServiceType(): string
    {
        return Provider::OAUTH_CLIENTS[AzureClient::class];
    }

    /**
     * @see Used to enforce https redirect finisher, not needed if we were
     * developing on https
     *
     * @return string
     */
    public function renderFinishAuthorizationUri(): string
    {
        $currentRequestHandler = $this->bootstrap->getActiveRequestHandler();
        if ($currentRequestHandler instanceof HttpRequestHandlerInterface) {
            $httpRequest = $currentRequestHandler->getComponentContext()->getHttpRequest();
        } else {
            putenv('FLOW_REWRITEURLS=1');
            $httpRequest = $this->serverRequestFactory->createServerRequest('GET', new Uri($this->flowBaseUriSetting));
        }
        $actionRequest = ActionRequest::fromHttpRequest($httpRequest);

        $this->uriBuilder->reset();
        $this->uriBuilder->setRequest($actionRequest);
        $this->uriBuilder->setCreateAbsoluteUri(true);

        try {
            $uri = $this->uriBuilder->
            reset()->
            setCreateAbsoluteUri(true)->
            uriFor('finishAuthorization', ['serviceType' => $this->getServiceType(), 'serviceName' => $this->getServiceName()], 'OAuth', 'Flownative.OAuth2.Client');
            $uri = stripos($uri, 'http:', 0) === false ? $uri : str_replace('http:', 'https:', $uri);
            return $uri;
        } catch (MissingActionNameException $e) {
            return '';
        }
    }

}
