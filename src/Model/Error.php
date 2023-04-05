<?php
/**
 * Error
 *
 * PHP version 5
 *
 * @category Class
 * @package  Maviance\S3PApiClient
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */

/**
 * Smobilpay S3P API
 *
 * Smobilpay Third Party API FOR PAYMENT COLLECTIONS
 *
 * OpenAPI spec version: 3.0.4
 *
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 * Swagger Codegen version: 3.0.24
 */
/**
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen
 * Do not edit the class manually.
 */

namespace Dy05Maviance\S3PApiClient\Model;

use \ArrayAccess;
use \Dy05Maviance\S3PApiClient\ObjectSerializer;

/**
 * Error Class Doc Comment
 *
 * @category Class
 * @package  Maviance\S3PApiClient
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class Error implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'Error';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'respCode' => 'int',
'devMsg' => 'string',
'usrMsg' => 'string',
'link' => 'string'    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'respCode' => 'int32',
'devMsg' => null,
'usrMsg' => null,
'link' => null    ];

    /**
     * Array of property to type mappings. Used for (de)serialization
     *
     * @return array
     */
    public static function swaggerTypes()
    {
        return self::$swaggerTypes;
    }

    /**
     * Array of property to format mappings. Used for (de)serialization
     *
     * @return array
     */
    public static function swaggerFormats()
    {
        return self::$swaggerFormats;
    }

    /**
     * Array of attributes where the key is the local name,
     * and the value is the original name
     *
     * @var string[]
     */
    protected static $attributeMap = [
        'respCode' => 'respCode',
'devMsg' => 'devMsg',
'usrMsg' => 'usrMsg',
'link' => 'link'    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'respCode' => 'setRespCode',
'devMsg' => 'setDevMsg',
'usrMsg' => 'setUsrMsg',
'link' => 'setLink'    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'respCode' => 'getRespCode',
'devMsg' => 'getDevMsg',
'usrMsg' => 'getUsrMsg',
'link' => 'getLink'    ];

    /**
     * Array of attributes where the key is the local name,
     * and the value is the original name
     *
     * @return array
     */
    public static function attributeMap()
    {
        return self::$attributeMap;
    }

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @return array
     */
    public static function setters()
    {
        return self::$setters;
    }

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @return array
     */
    public static function getters()
    {
        return self::$getters;
    }

    /**
     * The original name of the model.
     *
     * @return string
     */
    public function getModelName()
    {
        return self::$swaggerModelName;
    }



    /**
     * Associative array for storing property values
     *
     * @var mixed[]
     */
    protected $container = [];

    /**
     * Constructor
     *
     * @param mixed[] $data Associated array of property values
     *                      initializing the model
     */
    public function __construct(array $data = null)
    {
        $this->container['respCode'] = isset($data['respCode']) ? $data['respCode'] : null;
        $this->container['devMsg'] = isset($data['devMsg']) ? $data['devMsg'] : null;
        $this->container['usrMsg'] = isset($data['usrMsg']) ? $data['usrMsg'] : null;
        $this->container['link'] = isset($data['link']) ? $data['link'] : null;
    }

    /**
     * Show all the invalid properties with reasons.
     *
     * @return array invalid properties with reasons
     */
    public function listInvalidProperties()
    {
        $invalidProperties = [];

        if ($this->container['respCode'] === null) {
            $invalidProperties[] = "'respCode' can't be null";
        }
        if ($this->container['devMsg'] === null) {
            $invalidProperties[] = "'devMsg' can't be null";
        }
        if ($this->container['usrMsg'] === null) {
            $invalidProperties[] = "'usrMsg' can't be null";
        }
        if ($this->container['link'] === null) {
            $invalidProperties[] = "'link' can't be null";
        }
        return $invalidProperties;
    }

    /**
     * Validate all the properties in the model
     * return true if all passed
     *
     * @return bool True if all properties are valid
     */
    public function valid()
    {
        return count($this->listInvalidProperties()) === 0;
    }


    /**
     * Gets respCode
     *
     * @return int
     */
    public function getRespCode()
    {
        return $this->container['respCode'];
    }

    /**
     * Sets respCode
     *
     * @param int $respCode Unique error response code identifying the issue. We recommend you use this code for internal error handling.
     *
     * @return $this
     */
    public function setRespCode($respCode)
    {
        $this->container['respCode'] = $respCode;

        return $this;
    }

    /**
     * Gets devMsg
     *
     * @return string
     */
    public function getDevMsg()
    {
        return $this->container['devMsg'];
    }

    /**
     * Sets devMsg
     *
     * @param string $devMsg Verbose, plain language description of the problem for the app developer with hints about how to fix it, if applicable.
     *
     * @return $this
     */
    public function setDevMsg($devMsg)
    {
        $this->container['devMsg'] = $devMsg;

        return $this;
    }

    /**
     * Gets usrMsg
     *
     * @return string
     */
    public function getUsrMsg()
    {
        return $this->container['usrMsg'];
    }

    /**
     * Sets usrMsg
     *
     * @param string $usrMsg High level error message that can be passed on to the actual user - if required.
     *
     * @return $this
     */
    public function setUsrMsg($usrMsg)
    {
        $this->container['usrMsg'] = $usrMsg;

        return $this;
    }

    /**
     * Gets link
     *
     * @return string
     */
    public function getLink()
    {
        return $this->container['link'];
    }

    /**
     * Sets link
     *
     * @param string $link Link to documentation for this error response code – if available
     *
     * @return $this
     */
    public function setLink($link)
    {
        $this->container['link'] = $link;

        return $this;
    }
    /**
     * Returns true if offset exists. False otherwise.
     *
     * @param integer $offset Offset
     *
     * @return boolean
     */
    public function offsetExists($offset)
    {
        return isset($this->container[$offset]);
    }

    /**
     * Gets offset.
     *
     * @param integer $offset Offset
     *
     * @return mixed
     */
    public function offsetGet($offset)
    {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }

    /**
     * Sets value based on offset.
     *
     * @param integer $offset Offset
     * @param mixed   $value  Value to be set
     *
     * @return void
     */
    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * Unsets offset.
     *
     * @param integer $offset Offset
     *
     * @return void
     */
    public function offsetUnset($offset)
    {
        unset($this->container[$offset]);
    }

    /**
     * Gets the string presentation of the object
     *
     * @return string
     */
    public function __toString()
    {
        if (defined('JSON_PRETTY_PRINT')) { // use JSON pretty print
            return json_encode(
                ObjectSerializer::sanitizeForSerialization($this),
                JSON_PRETTY_PRINT
            );
        }

        return json_encode(ObjectSerializer::sanitizeForSerialization($this));
    }
}
