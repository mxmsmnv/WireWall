<?php namespace ProcessWire;
class WireData { private array $data=[];public function __get($k){return $this->data[$k]??null;} public function __set($k,$v){$this->data[$k]=$v;}public function get($k){return $this->__get($k);} }
class HookEvent {}
interface Module {} interface ConfigurableModule {}
require __DIR__.'/../WireWall.module.php';
require __DIR__.'/../src/Security/WireWallOwnerScannerVerifier.php';
class ScannerDenied extends \RuntimeException {}
class ScannerFlow extends WireWall {
 public object $cfg;public array $denials=[];public array $allowed=[];public string $forced='';public int $proxyLookups=0;
 public function __construct(public string $directory){$this->enabled=true;$this->rate_limit_enabled=true;$this->block_proxy_vpn_tor=true;$this->block_datacenters=true;$this->js_challenge_enabled=true;$this->enable_stats_logging=false;$this->cfg=(object)['urls'=>(object)['admin'=>'/admin/'],'cli'=>false,'wireWallOwnerScanner'=>null];}
 public function wire($name=null){return match($name){'config'=>$this->cfg,'user'=>new class{function isLoggedin(){return false;}},default=>null};}
 protected function isAllowedModuleRequest(){return false;}
 protected function getRealClientIP(){return '203.0.113.10';}
 protected function getPrivateDataPath(){return $this->directory.'/';}
 protected function isIPWhitelisted($ip){return false;}
 protected function getGeoData($ip){return ['country'=>'US','asn'=>'test'];}
 public function getOperationsStore(){return new class($this->forced){function __construct(private string $forced){} function matchEmergencyRule(...$a){return $this->forced==='emergency'?['id'=>'fixture','type'=>'ip']:null;}};}
 protected function isIPBanned($ip){return $this->forced==='ban';}
 protected function checkTriggerRules($ip,$ua,$uri){return $this->forced==='trigger'?'fixture-trigger':null;}
 protected function isRateLimited($ip){return $this->forced==='rate';}
 protected function isIPBlacklisted($ip){return $this->forced==='ip';}
 protected function verifyKnownBotIdentity($ua,$ip){return ['status'=>'unverified'];}
 protected function isAllowedBot($ua,$ip,$asn=null,$verifiedIdentity=false){return false;}
 protected function matchesCompatibilityUserAgent($ua){return false;}
 protected function isSuspiciousRequest($ua){return true;}
 protected function verifyChallengeCookie(){return true;}
 protected function isDatacenter($ip,$asn){return true;}
 public function getIpIntelligenceService(){++$this->proxyLookups;return new class{function lookup(...$a){return ['proxy_class'=>'unknown_proxy'];}function actionFor(...$a){return 'block';}};}
 protected function isProxyVPNTor($ip){return true;}
 public function getWireWallSettings(){return [];}
 protected function isBlockedASN($asn){return $this->forced==='asn';}
 protected function checkGlobalRules($ip,$ua,$path,$referer,$known=false,$compatibility=false){return $this->forced==='path';}
 protected function checkCountryBlocking($country){return $this->forced==='geo';}
 protected function checkCountryRules($country,$ua,$path,$referer){return false;}
 protected function blockAccess($reason,$ip,$country,$asn,$ua=''){throw new ScannerDenied($reason);}
 protected function recordTrafficHistory($ip,$country,$asn,$allowed,$reason,$ua=''){$this->allowed[]=[$allowed,$reason];}
 protected function logAccess($ip,$country,$asn,$allowed,$reason,$ua=''){}
}
function flowAssert(bool $ok,string $label){if(!$ok){fwrite(STDERR,"FAIL $label\n");exit(1);}}
$dir=sys_get_temp_dir().'/wirewall-flow-'.bin2hex(random_bytes(8));$w=new ScannerFlow($dir);
$pair=sodium_crypto_sign_keypair();$secret=sodium_crypto_sign_secretkey($pair);$public=sodium_crypto_sign_publickey($pair);$now=time();$key=substr(hash('sha256',$public),0,16);
$w->cfg->wireWallOwnerScanner=['host'=>'lqrs.com','issued_at'=>$now,'expires_at'=>$now+3600,'public_key'=>base64_encode($public)];
function flowRequest(bool $signed=true):array{global $now,$key,$secret;$s=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/','HTTP_HOST'=>'lqrs.com','HTTPS'=>'on','HTTP_USER_AGENT'=>'NucleiPrototype/0.6'];if(!$signed)return $s;$nonce=bin2hex(random_bytes(16));$s+=['HTTP_X_NUCLEI_SCANNER_KEY'=>$key,'HTTP_X_NUCLEI_SCANNER_TIME'=>(string)$now,'HTTP_X_NUCLEI_SCANNER_NONCE'=>$nonce,'HTTP_X_NUCLEI_SCANNER_SIGNATURE'=>base64_encode(sodium_crypto_sign_detached(WireWallOwnerScannerVerifier::message('lqrs.com','/',(string)$now,$nonce,$key),$secret))];return $s;}
try{
 $_SERVER=flowRequest();$w->checkAccess(new HookEvent());flowAssert($w->allowed===[[true,'signed-owner-scanner']]&&$w->proxyLookups===0,'signed network exception only');
 $_SERVER=flowRequest(false);try{$w->checkAccess(new HookEvent());flowAssert(false,'unsigned blocked');}catch(ScannerDenied $e){flowAssert($e->getMessage()==='proxy-class-unknown_proxy','unsigned original proxy protection');}
 $_SERVER=flowRequest();$_SERVER['HTTP_X_NUCLEI_SCANNER_SIGNATURE']=base64_encode(random_bytes(64));try{$w->checkAccess(new HookEvent());flowAssert(false,'forgery blocked');}catch(ScannerDenied $e){flowAssert($e->getMessage()==='proxy-class-unknown_proxy','forgery original protection');}
 foreach(['emergency','ban','trigger','rate','ip','asn','path','geo'] as $block){$w->forced=$block;$_SERVER=flowRequest();try{$w->checkAccess(new HookEvent());flowAssert(false,'signed cannot override '.$block);}catch(ScannerDenied $e){}}
 echo "WireWall real checkAccess flow: signed exception, unsigned/forged denial and eight independent defenses passed\n";
}finally{foreach(glob($dir.'/owner-scanner/*')?:[] as $f)unlink($f);if(is_dir($dir.'/owner-scanner'))rmdir($dir.'/owner-scanner');if(is_dir($dir))rmdir($dir);sodium_memzero($secret);}
