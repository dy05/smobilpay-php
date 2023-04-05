<?php
namespace Dy05Maviance\S3PApiClient;
use Exception;

class HMACSignature {
    private string $url;
    private string $method;
    private array $params;

    /**
     * This method generates the signature based on given parameters
     *
     * @param string $secret
     *
     * @return string
     */
    public function generate(string $secret): string
    {
        $encodedString = hash_hmac('sha1', $this->getBaseString(), $secret, true);
        return base64_encode($encodedString);
    }

    /**
     * @param string $method
     * @param string $url
     * @param array $params parameters to include in signature
     */
    public function __construct(string $method, string $url, array $params)
    {
        $this->method = $method;
        $this->url = $url;
        $this->params = $params;
    }

    /**
     * @param string $signature
     * @param string $secret
     *
     * @return bool
     * @throws Exception
     */
    public function verify(string $signature, string $secret): bool
    {
        if ($signature !== $this->generate($secret)) {
            throw new Exception("Signature Does Not Match");
        }

        return true;
    }

    /**
     * compile base string
     *
     * @return string
     */
    public function getBaseString(): string
    {
        $glue = "&";
        $sorted = $this->getParameterString();

        return
            // capitalize httptype
            strtoupper(trim($this->method)) . $glue .
            // urlencode url
            rawurlencode(trim($this->url)) . $glue .
            // lexically sorted parameter string
            $sorted;
    }

    /**
     * Prepares a string to be signed
     *
     * @param array $parameters
     *
     * @return string
     */
    protected function getParameterString(array $parameters = []): string
    {
        $glue = "&";
        $stringToBeSigned = '';
        // lexically sort parameters
        ksort($this->params);
        foreach ($this->params as $key => $value) {
            $stringToBeSigned .= trim($key) . '=' . trim($value) . $glue;
        }

        // urlencode and remove trailing glue
        return rawurlencode(trim(substr($stringToBeSigned, 0, -1)));
    }
}
