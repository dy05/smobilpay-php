<?php

namespace Dy05Maviance\S3PApiClient;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use Ramsey\Uuid\Uuid;

/**
 * ApiClient Class Doc Comment
 *
 * @category Class
 * @package  maviance\S3PApiClient
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class ApiClient extends Client {
    private string $token;
    private string $secret;

    public function __construct($token, $secret, array $config = [])
    {
        $this->token = $token;
        $this->secret = $secret;
        parent::__construct($config);
    }

    /**
     * @param RequestInterface $request
     * @param array $options
     * @return ResponseInterface
     * @throws GuzzleException
     */
    public function send(RequestInterface $request, array $options = []): ResponseInterface
    {
        $options['headers'] = ["Authorization" => $this->buildAuthorizationHeader($request)];
        return parent::send($request, $options);
    }

    /**
     * Build S3P Authorization Header
     * @param RequestInterface $request
     * @return string
     */
    function buildAuthorizationHeader(RequestInterface $request): string
    {
        $data = [];
        if ($request->getMethod() == "POST") {
            $data = json_decode($request->getBody()->getContents(), true);
        }

        $auth_titleKey = "s3pAuth";
        $auth_tokenKey = "s3pAuth_token";
        $auth_nonceKey = "s3pAuth_nonce";
        $auth_signatureKey = "s3pAuth_signature";
        $auth_signatureMethodKey = "s3pAuth_signature_method";
        $auth_timestampKey = "s3pAuth_timestamp";
        $separator = ", ";
        $signature_method = "HMAC-SHA1";
        $timestamp = time();
        $nonce = Uuid::uuid4()->toString();
        $params =
            array(
                "s3pAuth_nonce" => $nonce,
                "s3pAuth_timestamp" => $timestamp,
                "s3pAuth_signature_method" => $signature_method,
                "s3pAuth_token" => $this->token,
            );

        // dissect GET request query parameters
        if (!empty($request->getUri()->getQuery())) {
            $queryParameters = explode("&", urldecode($request->getUri()->getQuery()));
            foreach ($queryParameters as $param) {
                $item = explode("=", $param);
                $params[$item[0]] = $item[1];
            }
        }

        $sig = new HMACSignature(
            $request->getMethod(),
            $this->getUrl($request->getUri()),
            array_merge($data, $params)
        );

        $signature = $sig->generate($this->secret);
        return $auth_titleKey . " " . $auth_timestampKey . "=\"" . $timestamp . "\"" . $separator .
            $auth_signatureKey . "=\"" . $signature . "\"" . $separator .
            $auth_nonceKey . "=\"" . $nonce . "\"" . $separator .
            $auth_signatureMethodKey . "=\"" . $signature_method . "\"" . $separator .
            $auth_tokenKey . "=\"" . $this->token . "\"";
    }

    /**
     * Build url to use in signature validation
     * @param UriInterface $uri
     * @return string
     */
    private function getUrl(UriInterface $uri): string
    {
        // in case ports are not standard -> add to url
        return implode('',
            [
                $uri->getScheme(),
                "://",
                $uri->getHost(),
                is_null($uri->getPort()) ? "" : ((!in_array($uri->getPort(), [80, 443])) ? ":" . $uri->getPort() : ""),
                $uri->getPath()
            ]);
    }
}
