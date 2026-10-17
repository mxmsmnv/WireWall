<?php namespace ProcessWire;
require __DIR__ . '/../src/Security/WireWallOwnerScannerVerifier.php';
function scannerAssert(bool $ok, string $label): void { if (!$ok) { fwrite(STDERR, "FAIL: $label\n"); exit(1); } }
$dir=sys_get_temp_dir().'/wirewall-owner-'.bin2hex(random_bytes(8));
$pair=sodium_crypto_sign_keypair();$private=sodium_crypto_sign_secretkey($pair);$public=sodium_crypto_sign_publickey($pair);
$now=time();$key=substr(hash('sha256',$public),0,16);$grant=['host'=>'lqrs.com','issued_at'=>$now,'expires_at'=>$now+3600,'public_key'=>base64_encode($public)];
function request(array $change=[]): array {
    global $now,$key,$private;
    $s=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/','HTTP_HOST'=>'lqrs.com','HTTPS'=>'on','HTTP_X_NUCLEI_SCANNER_KEY'=>$key,'HTTP_X_NUCLEI_SCANNER_TIME'=>(string)$now,'HTTP_X_NUCLEI_SCANNER_NONCE'=>bin2hex(random_bytes(16))];
    $s=array_replace($s,$change);
    $s['HTTP_X_NUCLEI_SCANNER_SIGNATURE']=base64_encode(sodium_crypto_sign_detached(WireWallOwnerScannerVerifier::message($s['HTTP_HOST'],$s['REQUEST_URI'],$s['HTTP_X_NUCLEI_SCANNER_TIME'],$s['HTTP_X_NUCLEI_SCANNER_NONCE'],$s['HTTP_X_NUCLEI_SCANNER_KEY']),$private));
    return $s;
}
try {
 $v=new WireWallOwnerScannerVerifier($dir);$one=request();scannerAssert($v->verify($one,$grant,$now),'valid signature');scannerAssert(!$v->verify($one,$grant,$now),'replay rejected');
 foreach ([['REQUEST_METHOD'=>'POST'],['REQUEST_URI'=>'/admin/'],['REQUEST_URI'=>'/?q=1'],['REQUEST_URI'=>'/%2eenv'],['REQUEST_URI'=>'//.env'],['REQUEST_URI'=>'/.env/'],['HTTP_HOST'=>'www.lqrs.com'],['HTTP_HOST'=>'lqrs.com:443'],['HTTPS'=>'off'],['HTTP_X_NUCLEI_SCANNER_TIME'=>(string)($now-31)],['HTTP_X_NUCLEI_SCANNER_TIME'=>(string)($now+6)]] as $change) scannerAssert(!$v->verify(request($change),$grant,$now),'scope or timestamp rejected');
 $bad=request();$bad['REQUEST_URI']='/.env';scannerAssert(!$v->verify($bad,$grant,$now),'signature bound to path');
 $bad=request();$bad['HTTP_X_NUCLEI_SCANNER_SIGNATURE']=base64_encode(random_bytes(64));scannerAssert(!$v->verify($bad,$grant,$now),'forged signature');
 scannerAssert(!$v->verify([], $grant, $now),'no headers');
 scannerAssert(!$v->verify(request(),array_replace($grant,['expires_at'=>$now]),$now),'expired grant');
 scannerAssert(!$v->verify(request(),array_replace($grant,['expires_at'=>$now+3601]),$now),'overlong grant');
 scannerAssert(!$v->verify(request(),array_replace($grant,['public_key'=>base64_encode(random_bytes(32))]),$now),'wrong public key');
 foreach (['/.git/config','/.env','/phpinfo.php','/info.php'] as $path) scannerAssert($v->verify(request(['REQUEST_URI'=>$path]),$grant,$now),'reviewed GET path');
 for($i=0;$i<5;$i++) scannerAssert($v->verify(request(),$grant,$now),'budget within ten');
 scannerAssert(!$v->verify(request(),$grant,$now),'per-minute cap');
 $state=$dir.'/'.$key.'.json';file_put_contents($state,'{corrupt');scannerAssert(!$v->verify(request(),$grant,$now),'corrupt state fails closed');
 unlink($state);symlink($dir.'/missing',$state);scannerAssert(!$v->verify(request(),$grant,$now),'state symlink rejected');unlink($state);
 $originalNow=$now;
 for($i=0;$i<60;$i++) {$now=$originalNow+intdiv($i,10)*61;scannerAssert($v->verify(request(),$grant,$now),'hourly budget within sixty');}
 $now=$originalNow+366;scannerAssert(!$v->verify(request(),$grant,$now),'hourly cap sixty');
 $now=$originalNow;
 echo "Owner scanner scope, signature, expiry, replay, budget and state checks passed\n";
} finally {
 foreach(glob($dir.'/*')?:[] as $p)unlink($p);if(is_dir($dir))rmdir($dir);
 sodium_memzero($private);
}
