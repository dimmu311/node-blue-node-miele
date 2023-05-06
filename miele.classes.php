<?php
declare(strict_types=1);

class MieleSettings
{
	public $userId = '';
    public $password = '';
    public $clientId = '';
    public $clientSecret = '';
    public $country = '';
    public $language = '';
    public $nodeId = '';
}

class MieleRest
{
	private $settings = NULL;
    private $authorizationCode = '';
    private $accessToken = '';
    private $refreshToken = '';
    private $tokenExpiresAt = '';
    private $deviceData = array();

    public function __construct(MieleSettings $settings){
        $this->settings = $settings;
    }

    private function curlRequest($url, $method, $contentType, $data, $token, &$responseCode){
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $headers = array();
        if($contentType) $headers[] = 'Content-Type: '.$contentType;
        if($token) $headers[] = 'Authorization: Bearer '.urlencode($token);
        if(count($headers) > 0) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if($method == 'POST' || $method == 'PUT') curl_setopt($ch, CURLOPT_POSTFIELDS, $data);

        $result = curl_exec($ch);
        $returnValue = false;
        if($result !== false){
            $responseCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            if($responseCode == 302) $returnValue = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
            else if($responseCode >= 200 && $responseCode < 300) $returnValue = $result;
        }
        curl_close($ch);
	    return $returnValue;
    }

    private function calculateTokenExpireDate($expiresIn){
        $date = new DateTime();
        $date->add(new DateInterval('PT'.$expiresIn.'S'));
        HomegearNodeBase::log(4, 'token expires in: '. $expiresIn. ' so at: '. date_format($date, 'Y-m-d H:i:s'));
        return $date->getTimestamp();
    }

    private function login(){
        $this->accessToken = '';
        if($this->refreshToken && $this->settings->clientId && $this->settings->clientSecret){
            $url = 'https://api.mcs3.miele.com/thirdparty/token?client_id='.urlencode($this->settings->clientId).'&client_secret='.urlencode($this->settings->clientSecret).'&refresh_token='.urlencode($this->refreshToken).'&redirect_uri=%2Fv1%2Fdevices&grant_type=refresh_token&state=token';
            $responseCode = 0;
            $result = $this->curlRequest($url, 'GET', '', '', '', $responseCode);
            if($result === false || $responseCode == 0){
                HomegearNodeBase::log(2, 'Unknown error using refresh token. (response code '.$responseCode.'): '.$result);
                //todo check if this works. i think returning false here result in a loop with trying to use refresh token that is no more usable.
                //return false;
            }
            else if($responseCode == 200){
                $tokens = json_decode($result, true);
                $this->accessToken = $tokens['access_token'] ?? '';
                $this->refreshToken = $tokens['refresh_token'] ?? '';
                $this->tokenExpiresAt = $this->calculateTokenExpireDate($tokens['expires_in']);
                
                if($this->accessToken){
                    HomegearNodeBase::log(4, 'Successfully refreshed access token. (response code '.$responseCode.'): '.$result);
                    return true;
                }
            }
        }

        if($this->settings->userId && $this->settings->password && $this->settings->clientId && $this->settings->clientSecret && $this->settings->country){
            $this->authorizationCode = '';

            $url = 'https://api.mcs3.miele.com/oauth/auth';
            $data = 'email='.urlencode($this->settings->userId).'&password='.urlencode($this->settings->password).'&redirect_uri=%2Fv1%2Fdevices&state=login&response_type=code&client_id='.urlencode($this->settings->clientId).'&vgInformationSelector='.urlencode($this->settings->country);
            $responseCode = 0;
            $result = $this->curlRequest($url, 'POST', 'application/x-www-form-urlencoded', $data, '', $responseCode);
            if($result === false || $responseCode == 0){
                HomegearNodeBase::log(2, 'Unknown error obtaining authorization code. (response code '.$responseCode.'): '.$result);
                return false;
            }
            else if($responseCode == 302){
                if(is_string($result)){
                    $parameters = explode('?', $result);
                    if(count($parameters) > 1){
                        $parameters = $parameters[1];
                        $parameters = explode('&', $parameters);
                        foreach($parameters as $parameter){
                            $parameter = explode('=', $parameter);
                            if(count($parameter) == 2 && $parameter[0] == 'code') $this->authorizationCode = $parameter[1];
                            HomegearNodeBase::log(4, 'Successfully get authorizationCode (response code '.$responseCode.'): '.$result);
                        }
                    }
                }
            }
            else{
                HomegearNodeBase::log(2, 'Error obtaining authorization code (response code '.$responseCode.'): '.$result);
            }

            if($this->authorizationCode){
                $url = 'https://api.mcs3.miele.com/thirdparty/token?client_id='.urlencode($this->settings->clientId).'&client_secret='.urlencode($this->settings->clientSecret).'&code='.urlencode($this->authorizationCode).'&redirect_uri=%2Fv1%2Fdevices&grant_type=authorization_code&state=token';
                $responseCode = 0;
                $result = $this->curlRequest($url, 'POST', 'application/x-www-form-urlencoded', '', '', $responseCode);
                if($result === false || $responseCode == 0){
                    HomegearNodeBase::log(2, 'Unknown error obtaining access token. (response code '.$responseCode.'): '.$result);
                    return false;
                }
                else if($responseCode == 200){
                    $tokens = json_decode($result, true);
                    $this->accessToken = $tokens['access_token'] ?? '';
                    $this->refreshToken = $tokens['refresh_token'] ?? '';
                    $this->tokenExpiresAt = $this->calculateTokenExpireDate($tokens['expires_in']);

                    if($this->accessToken){
                        HomegearNodeBase::log(4, 'Successfully obtained access token. (response code '.$responseCode.'): '.$result);
                        return true;
                    }
                }
                else{
                    HomegearNodeBase::log(2, 'Error obtaining access token (response code '.$responseCode.'): '.$result);
                    return false;
                }
            }
        }
        else{
            HomegearNodeBase::log(2, 'Node is not fully configured.');
        }

        return false;
    }

    private function refreshToken(){
        $url = 'https://api.mcs3.miele.com/thirdparty/token';
        $data = 'client_id='. urlencode($this->settings->clientId). '&client_secret='. urlencode($this->settings->clientSecret). '&refresh_token='. $this->refreshToken . '&grant_type=refresh_token';
	    $responseCode = 0;
        $result = $this->curlRequest($url, 'POST', 'application/x-www-form-urlencoded', $data, '', $responseCode);
        if($result === false || $responseCode == 0){
            HomegearNodeBase::log(2, 'Unknown error refreshing token. (response code '.$responseCode.'): '.$result);
            return false;
        }
        else if($responseCode == 200){
            $tokens = json_decode($result, true);
            $this->accessToken = $tokens['access_token'] ?? '';
            $this->refreshToken = $tokens['refresh_token'] ?? '';
            $this->tokenExpiresAt = $this->calculateTokenExpireDate($tokens['expires_in']);

            if($this->accessToken){
                HomegearNodeBase::log(4, 'Successfully refreshed access token (response code '.$responseCode.'): '.$result);
                return true;
            }
        }
        else{
            HomegearNodeBase::log(2, 'Error refreshing access token (response code '.$responseCode.'): '.$result);
            return false;
        }
    }

    private function restRequest($url, $method, $contentType = '', $data = '', &$responseCode = 0){
        if(!$this->accessToken){
            if($this->login() === false) return false;
        }

        $result = $this->curlRequest($url, $method, $contentType, $data, $this->accessToken, $responseCode);
        if($result === false || $responseCode == 0){
            HomegearNodeBase::log(2, 'Unknown error calling URL '.$url.'. (response code '.$responseCode.'): '.$result);
            return false;
        }
        else if($responseCode == 401){
            HomegearNodeBase::log(2, 'Error 401 calling URL '.$url.' trying to login again');
            if($this->login() === false) return false;
            $result = $this->curlRequest($url, $method, $contentType, $data, $this->accessToken, $responseCode);
        }

        if($responseCode >= 200 && $responseCode < 300) return json_decode($result, true);
        else{
            HomegearNodeBase::log(2, 'Error calling URL '.$url.' (response code '.$responseCode.'): '.$result);
        }

        return false;
    }

    public function logout(){
        $url = 'https://api.mcs3.miele.com/thirdparty/logout';
        $responseCode = 0;
        $result = $this->curlRequest($url, 'POST', 'application/x-www-form-urlencoded', '', $this->accessToken, $responseCode);
        
        if($result === false || $responseCode == 0){
            HomegearNodeBase::log(2, 'Unknown error calling URL '.$url.'. (response code '.$responseCode.'): '.$result);
            return false;
        }
        else if($responseCode == 204){
            HomegearNodeBase::log(4, 'Successfully logged out (response code '.$responseCode.'): '.$result);
            $this->accessToken = '';
            $this->refreshToken = '';
            $this->tokenExpiresAt = '';
            return true;
        }
    }

    public function getDevices(){
        $responseCode = 0;
	    return $this->restRequest('https://api.mcs3.miele.com/v1/devices/'.($this->settings->language ? '?language='.urlencode($this->settings->language) : ''), 'GET', '', $responseCode = 0);
    }

    public function processDevices($devices){
        foreach ($devices as $device){
            $deviceData = array();
            $serialNumber = $device['ident']['deviceIdentLabel']['fabNumber'] ?? '';
            if(!$serialNumber) continue;
            $deviceData['serialNumber'] = $serialNumber;
            $deviceData['typeId'] = $device['ident']['type']['value_raw'] ?? 0;
            $deviceData['typeLabel'] = $device['ident']['type']['value_localized'] ?? '';
            $deviceData['deviceName'] = $device['ident']['deviceName'] ?? '';
            $deviceData['state'] = $device['state'] ?? NULL;
            $deviceData['hash'] = md5(serialize($deviceData));

            $url='https://api.mcs3.miele.com/v1/devices/'. $device . '/events' .($this->settings->language ? '?language='.urlencode($this->settings->language) : '');
            $method='GET';
            //fixme: $devive must be string not struct
            //$data = $this->restRequest($url, $method, '', '');
            //\Homegear\Homegear::nodeOutput($this->settings->nodeId, 0, array('payload' => $data));


            if(isset($this->deviceData[$serialNumber]) && isset($this->deviceData[$serialNumber]['hash']) && $this->deviceData[$serialNumber]['hash'] == $deviceData['hash']){
                //continue;
                //fixme: do something that a device with no changes since the last poll would call nodeOutput()
            }
            $this->deviceData[$serialNumber] = $deviceData;
            \Homegear\Homegear::nodeOutput($this->settings->nodeId, 0, array('payload' => $deviceData));
        }
    }

    public function checkTocken(){
        if(!$this->tokenExpiresAt) return false;
        $date = new DateTime();
        $timeRemaining = $this->tokenExpiresAt - ($date->getTimestamp());

        HomegearNodeBase::log(5, 'The token can be used for '. $timeRemaining. 's until it need\'s to be refreshed');

        if($timeRemaining < 86400){ // less than one day
            HomegearNodeBase::log(4, 'The token can be used for less than one Day, so we try to refresh');
            $this->refreshToken();
            return true;
        }
    }

    public function getActions($msg){
        if(!isset($msg['device'])) return false;

        $device = $msg['device'];

        $url='https://api.mcs3.miele.com/v1/devices/'. $device . '/actions' .($this->settings->language ? '?language='.urlencode($this->settings->language) : '');
        $method='GET';
        
        $responseCode = 0;
        $data = $this->restRequest($url, $method, '', '', $responseCode);
        if($responseCode == 200){
            HomegearNodeBase::log(4, 'Result of getActions(): '. $data);
            \Homegear\Homegear::nodeOutput($this->settings->nodeId, 1, array('payload' => $data));
        }
        elseif($responseCode == 204){
            $data = true;
            HomegearNodeBase::log(4, 'Result of getActions(): '. $data);
            \Homegear\Homegear::nodeOutput($this->settings->nodeId, 1, array('payload' => $data));
        }
        else {
            HomegearNodeBase::log(2, 'Error during getActions() '.$url.' (response code '.$responseCode. ')');
        }
    }
    
    public function getEvents(){
        $device = 'all';
        $url='https://api.mcs3.miele.com/v1/devices/'. $device . '/events' .($this->settings->language ? '?language='.urlencode($this->settings->language) : '');
        $method='GET';
        
        $responseCode = 0;
        $data = $this->restRequest($url, $method, '', '', $responseCode);
        \Homegear\Homegear::nodeOutput($this->settings->nodeId, 3, array('payload' => $data));
    }

    public function setValue($msg){
        if(!isset($msg['action'])) return false;
        if(!isset($msg['state'])) return false;
        if(!isset($msg['device'])) return false;

        $action = $msg['action'];
        $state = $msg['state'];
        $device = $msg['device'];

        $url='https://api.mcs3.miele.com/v1/devices/'. $device . '/actions' .($this->settings->language ? '?language='.urlencode($this->settings->language) : '');
        $method='PUT';
        $data = json_encode(array($action=>$state));

        $responseCode = 0;
        $this->restRequest($url, $method, 'application/json', $data, $responseCode);

        $data = false;
        if ($responseCode == 204){
            $data = true;
            HomegearNodeBase::log(4, 'Result of setValue(): '. $data);
            \Homegear\Homegear::nodeOutput($this->settings->nodeId, 2, array('payload' => $data));
        }
        else {
            HomegearNodeBase::log(2, 'Error during setValue() '.$url.' (response code '.$responseCode. ')');
        }
    }   
}
