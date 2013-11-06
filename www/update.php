<?php

$IP = $_SERVER['REMOTE_ADDR'];
$HOSTNAME = $_REQUEST['hostname'];
$USERNAME = "";
$PASSWORD = "";

if(!isset($HOSTNAME))
  exit(1);

if(isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
  $USERNAME=$_SERVER['PHP_AUTH_USER'];
  $PASSWORD=$_SERVER['PHP_AUTH_PW'];
}
elseif(isset($_GET['username']) && isset($_GET['password'])) {
  $USERNAME=$_GET['username'];
  $PASSWORD=$_GET['password'];
}
else
  authFail();

try {
  $db = new PDO("sqlite:/var/lib/powerdns/pdns.sqlite3");
} catch(PDOException $e) {
  echo $e->getMessage();
}

$dbh = $db->prepare("SELECT users.id AS id,users.password AS password FROM hostnames LEFT JOIN users ON hostnames.userid=users.id WHERE hostname=:hostname");
$dbh->bindparam(':hostname', $HOSTNAME);
$dbh->execute();
$dbr=$dbh->fetch(PDO::FETCH_LAZY);

if(!isset($dbr['id']) || !isset($dbr['password']) ||
    $dbr['id']!=$USERNAME || crypt($PASSWORD,$dbr['password'])!=$dbr['password']) {
  authFail();
}

$dbh = $db->prepare("SELECT content FROM records WHERE name=:name");
$dbh->bindparam(':name', $HOSTNAME);
$dbh->execute();
$dbr=$dbh->fetch(PDO::FETCH_LAZY);

if ($dbr['content'] !== $IP) {
    $dbh = $db->prepare("update records set content=:content where name=:name");
    // $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $dbh->bindparam(':content', $IP);
    $dbh->bindparam(':name', $HOSTNAME);
    $dbh->execute();

    updateSerial();
}
print("Success.");

// $dbh->debugDumpParams();

function authFail() {
  header('WWW-Authenticate: Basic realm="My Realm"');
  header('HTTP/1.0 401 Unauthorized');
  exit(1);
}

function updateSerial() {
  global $db;

  $dbh = $db->prepare("select content from records where type='SOA'");
  $dbh->setFetchMode(PDO::FETCH_ASSOC);
  $dbh->execute();
  $row = $dbh->fetch();

  if(!isset($row['content']))
    die;

  preg_match("/([^\s]+) ([^\s]+) (\d+) (\d+) (\d+) (\d+) (\d+)/", $row['content'], $match);

  if(!isset($match[3]))
    die;
  $dbh = $db->prepare("update records set content=:content where type='SOA'");
  $dbh->bindparam(':content', sprintf("%s %s %d %d %d %d %d", $match[1], $match[2], $match[3]+1, $match[4], $match[5], $match[6], $match[7]));
  $dbh->execute();
}
