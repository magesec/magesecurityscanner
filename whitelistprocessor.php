<?php
ini_set('memory_limit','1024M');

$whitelisttype = $argv[2];
$workingdir = $argv[3];
$rawlist=file_get_contents($workingdir.'/'.$argv[1]);
if ($whitelisttype == 'size') {
  $rawwhitelist = file_get_contents($workingdir.'/filesizewhitelist.json');
  $delimiter = ' ';
} else {
  $rawwhitelist = file_get_contents($workingdir.'/sha1whitelist.json');
  $delimiter = '  ';
}
$whitelist = (array)json_decode($rawwhitelist);
$lines = explode("\n",$rawlist);


$scanlist = array();
#if ($whitelisttype == 'hash' ) {
  foreach ($lines as $line) {
    $split = explode($delimiter,$line);
    if (count($split) > 1) {
      $scanlist[$split[1]] = $split[0];
    }
  }
#} else {
#  foreach ($lines as $line) {
#     $split = explode(' ',$line);
#     if (count($split) > 1) {
#       $scanlist[$split[8]] = $split[4];
#     }
#  }
#}
foreach ($scanlist as $file => $hash) {
  $basename = basename($file);
  #print $hash.' '.$file."\n";
  if (isset($whitelist[$basename])) {
    if (in_array($hash,$whitelist[$basename])) {
      unset($scanlist[$file]);
      #print 'matched: '.$hash.' '.$file."\n";
    }
  }
}

$scanfile = '';
foreach ($scanlist as $file=>$hash) { 
  $scanfile .= $file."\n";
}

file_put_contents($workingdir.'/'.$argv[1],$scanfile);
?>
