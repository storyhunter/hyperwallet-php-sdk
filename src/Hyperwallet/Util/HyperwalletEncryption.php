<?php
namespace Hyperwallet\Util;

use Hyperwallet\Exception\HyperwalletException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;

/**
 * The encryption service for Hyperwallet client's requests/responses
 *
 * @package Hyperwallet\Util
 */
class HyperwalletEncryption {

    /**
     * String that can be a URL or path to file with client JWK set
     *
     * @var string
     */
    private $clientPrivateKeySetLocation;

    /**
     * String that can be a URL or path to file with hyperwallet JWK set
     *
     * @var string
     */
    private $hyperwalletKeySetLocation;

    /**
     * JWE encryption algorithm, by default value = RSA-OAEP-256
     *
     * @var string
     */
    private $encryptionAlgorithm;

    /**
     * JWS signature algorithm, by default value = RS256
     *
     * @var string
     */
    private $signAlgorithm;

    /**
     * JWE encryption method, by default value = A256CBC-HS512
     *
     * @var string
     */
    private $encryptionMethod;

    /**
     * Minutes when JWS signature is valid, by default value = 5
     *
     * @var integer
     */
    private $jwsExpirationMinutes;

    /**
     * JWS key id header param
     *
     * @var string
     */
    private $jwsKid;

    /**
     * JWE key id header param
     *
     * @var string
     */
    private $jweKid;

    /**
     * Creates a instance of the HyperwalletEncryption
     *
     * @param string $clientPrivateKeySetLocation String that can be a URL or path to file with client JWK set
     * @param string $hyperwalletKeySetLocation String that can be a URL or path to file with hyperwallet JWK set
     * @param string $encryptionAlgorithm JWE encryption algorithm, by default value = RSA-OAEP-256
     * @param string $signAlgorithm JWS signature algorithm, by default value = RS256
     * @param string $encryptionMethod JWE encryption method, by default value = A256CBC-HS512
     * @param integer $jwsExpirationMinutes Minutes when JWS signature is valid, by default value = 5
     */
    public function __construct(
        $clientPrivateKeySetLocation,
        $hyperwalletKeySetLocation,
        $encryptionAlgorithm = 'RSA-OAEP-256',
        $signAlgorithm = 'RS256',
        $encryptionMethod = 'A256CBC-HS512',
        $jwsExpirationMinutes = 5
    ) {
        $this->clientPrivateKeySetLocation = $clientPrivateKeySetLocation;
        $this->hyperwalletKeySetLocation = $hyperwalletKeySetLocation;
        $this->encryptionAlgorithm = $encryptionAlgorithm;
        $this->signAlgorithm = $signAlgorithm;
        $this->encryptionMethod = $encryptionMethod;
        $this->jwsExpirationMinutes = $jwsExpirationMinutes;
    }

    /**
     * Makes an encrypted request : 1) signs the request body; 2) encrypts payload after signature
     *
     * @param string $body The request body to be encrypted
     * @return string
     *
     * @throws HyperwalletException
     */
    public function encrypt($body) {
        $privateJwsKey = $this->getPrivateJwsKey();

        $algorithmManager = new AlgorithmManager([new RS256()]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $payload = json_encode($body);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($privateJwsKey, [
                'alg' => $this->signAlgorithm,
                'kid' => $this->jwsKid,
                'exp' => $this->getSignatureExpirationTime(),
            ])
            ->build();
        $jwsSerializer = new JWSCompactSerializer();
        $jwsToken = $jwsSerializer->serialize($jws, 0);

        $publicJweKey = $this->getPublicJweKey();
        $encAlgorithmManager = new AlgorithmManager([new RSAOAEP256(), new A256CBCHS512()]);
        $jweBuilder = new JWEBuilder($encAlgorithmManager);
        $jwe = $jweBuilder
            ->create()
            ->withPayload($jwsToken)
            ->withSharedProtectedHeader([
                'alg' => $this->encryptionAlgorithm,
                'enc' => $this->encryptionMethod,
                'kid' => $this->jweKid,
            ])
            ->addRecipient($publicJweKey)
            ->build();
        $jweSerializer = new JWECompactSerializer();
        return $jweSerializer->serialize($jwe, 0);
    }

    /**
     * Decrypts encrypted response : 1) decrypts the request body; 2) verifies the payload signature
     *
     * @param string $body The response body to be decrypted
     * @return array
     *
     * @throws HyperwalletException
     */
    public function decrypt($body) {
        $privateJweKey = $this->getPrivateJweKey();

        try {
            $encAlgorithmManager = new AlgorithmManager([new RSAOAEP256(), new A256CBCHS512()]);
            $jweDecrypter = new JWEDecrypter($encAlgorithmManager, null);
            $jweSerializer = new JWECompactSerializer();
            $jwe = $jweSerializer->unserialize($body);
            if (!$jweDecrypter->decryptUsingKey($jwe, $privateJweKey, 0)) {
                throw new HyperwalletException('Decryption error');
            }
        } catch (HyperwalletException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new HyperwalletException('Decryption error');
        }
        $decryptedPayload = $jwe->getPayload();

        $publicJwsKey = $this->getPublicJwsKey();
        $algorithmManager = new AlgorithmManager([new RS256()]);
        $jwsVerifier = new JWSVerifier($algorithmManager);
        $jwsSerializer = new JWSCompactSerializer();
        $jws = $jwsSerializer->unserialize($decryptedPayload);

        $this->checkJwsExpiration($jws->getSignature(0)->getProtectedHeader());

        if (!$jwsVerifier->verifyWithKey($jws, $publicJwsKey, 0)) {
            throw new HyperwalletException('Signature verification failed');
        }

        return json_decode($jws->getPayload(), true);
    }

    /**
     * Retrieves JWS JWK private key with algorithm = $this->signAlgorithm
     *
     * @return JWK
     *
     * @throws HyperwalletException
     */
    private function getPrivateJwsKey() {
        $keyData = $this->getJwk($this->clientPrivateKeySetLocation, $this->signAlgorithm);
        $this->jwsKid = $keyData['kid'];
        return new JWK($keyData);
    }

    /**
     * Retrieves JWE JWK public key with algorithm = $this->encryptionAlgorithm
     *
     * @return JWK
     *
     * @throws HyperwalletException
     */
    private function getPublicJweKey() {
        $keyData = $this->getJwk($this->hyperwalletKeySetLocation, $this->encryptionAlgorithm);
        $this->jweKid = $keyData['kid'];
        return new JWK($this->convertPrivateKeyToPublic($keyData));
    }

    /**
     * Retrieves JWE JWK private key with algorithm = $this->encryptionAlgorithm
     *
     * @return JWK
     *
     * @throws HyperwalletException
     */
    private function getPrivateJweKey() {
        $keyData = $this->getJwk($this->clientPrivateKeySetLocation, $this->encryptionAlgorithm);
        return new JWK($keyData);
    }

    /**
     * Retrieves JWS JWK public key with algorithm = $this->signAlgorithm
     *
     * @return JWK
     *
     * @throws HyperwalletException
     */
    private function getPublicJwsKey() {
        $keyData = $this->getJwk($this->hyperwalletKeySetLocation, $this->signAlgorithm);
        return new JWK($this->convertPrivateKeyToPublic($keyData));
    }

    /**
     * Retrieves JWK key by JWK key set location and algorithm
     *
     * @param string $keySetLocation The location(URL or path to file) of JWK key set
     * @param string $alg The target algorithm
     * @return array
     *
     * @throws HyperwalletException
     */
    private function getJwk($keySetLocation, $alg) {
        if (filter_var($keySetLocation, FILTER_VALIDATE_URL) === FALSE) {
            if (!file_exists($keySetLocation)) {
                throw new HyperwalletException("Wrong JWK key set location path = " . $keySetLocation);
            }
        }
        return $this->findJwkByAlgorithm(json_decode(file_get_contents($keySetLocation), true), $alg);
    }

    /**
     * Retrieves JWK key from JWK key set by given algorithm
     *
     * @param array $jwkSetArray JWK key set
     * @param string $alg The target algorithm
     * @return array
     *
     * @throws HyperwalletException
     */
    private function findJwkByAlgorithm($jwkSetArray, $alg) {
        foreach($jwkSetArray['keys'] as $jwk) {
            if ($alg == $jwk['alg']) {
                return $jwk;
            }
        }
        throw new HyperwalletException("JWK set doesn't contain key with algorithm = " . $alg);
    }

    /**
     * Converts private key to public by removing private components
     *
     * @param array $jwk JWK key data
     * @return array
     */
    private function convertPrivateKeyToPublic($jwk) {
        unset($jwk['d'], $jwk['p'], $jwk['q'], $jwk['qi'], $jwk['dp'], $jwk['dq']);
        return $jwk;
    }

    /**
     * Calculates JWS expiration time in seconds
     *
     * @return integer
     */
    private function getSignatureExpirationTime() {
        date_default_timezone_set("UTC");
        $secondsInMinute = 60;
        return time() + $this->jwsExpirationMinutes * $secondsInMinute;
    }

    /**
     * Checks if header 'exp' param has not expired value
     *
     * @param array $header JWS header array
     *
     * @throws HyperwalletException
     */
    public function checkJwsExpiration($header) {
        if(!isset($header['exp'])) {
            throw new HyperwalletException('While trying to verify JWS signature no [exp] header is found');
        }
        $exp = $header['exp'];
        if(!is_numeric($exp)) {
            throw new HyperwalletException('Wrong value in [exp] header of JWS signature, must be integer');
        }
        if((int)time() > (int)$exp) {
            throw new HyperwalletException('JWS signature has expired, checked by [exp] JWS header');
        }
    }
}
