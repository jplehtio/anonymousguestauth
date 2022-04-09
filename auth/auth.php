
<?php

	function auth(){

		session_start();

		if (isset($_SESSION["user_id"])){
			return;
		}

		if(isset($_COOKIE["aga_userid"])){
			
			loginWithCookie();

		}elseif ( isset($_GET["loginid"]) ){

			loginWithId($_GET["loginid"]);

		}elseif (isset($_POST["username"]) && isset($_POST["password"])){

			loginWithPassword($_POST["username"], $_POST["password"]);

		}else{

			createNewUser();

		}
	}

	function getUserId(){
		return $_SESSION["user_id"];
	}

	function getOwnedId(){
		return $_SESSION["owner_id"];
	}

	function loginWithId(string $id){

		if(strlen($id) != 32)
			return false;

		$userInfo = getUserInfo("SELECT user_id, username, owner_id FROM auth WHERE login_id = :loginid", array("loginid" => $id));
		
		if (count($userInfo) == 1){
			setLoginCookie($userInfo);
			return true;
		}

		return false;

	}

	function loginWithPassword(string $username, string $password){

		$userInfo = getUserInfo("SELECT user_id, username, password, owner_id FROM auth WHERE username = :username", array("username" => $username));

		if(count($userInfo) == 1 && password_verify($password, $userInfo[0]["password"])){
			setLoginCookie($userInfo);
			return true;
		}

		return false;

	}

	function loginWithCookie(){

		$userId = $_COOKIE["aga_userid"];
		
		$userInfo = getUserInfo("SELECT owner_id FROM auth WHERE user_id = :user_id", array("user_id" => $userId));

		$_SESSION["user_id"] = $userId;
		$_SESSION["owner_id"] = $userInfo[0]["owner_id"];
	}

	function getUserInfo($query, $details){
		$dbconf = parse_ini_file("db.conf");
		
		$db = new PDO("mysql:host={$dbconf["server"]};dbname={$dbconf["db"]}", $dbconf["user"], $dbconf["password"]);
		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		$userInfoQuery = $db->prepare($query);
		$userInfoQuery->execute($details);

		$userInfo = $userInfoQuery->fetchAll();
		$db = null;

		return $userInfo;
	}

	function setLoginCookie($userInfo){

		setcookie("aga_userid", $userInfo[0]["user_id"], time() + 315360000, "/");
		setcookie("aga_username", $userInfo[0]["username"], time() + 315360000, "/");

		$_SESSION["user_id"] = $userInfo[0]["user_id"];
		$_SESSION["owner_id"] = $userInfo[0]["owner_id"];

	}

	function createNewUser(){
		$userId = base64_encode(openssl_random_pseudo_bytes(24, $cstrong));
		$ownerId = base64_encode(openssl_random_pseudo_bytes(24, $cstrong));

		$dbconf = parse_ini_file("db.conf");
		
		$db = new PDO("mysql:host={$dbconf["server"]};dbname={$dbconf["db"]}", $dbconf["user"], $dbconf["password"]);
		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		$userInfoQuery = $db->prepare("INSERT INTO auth (user_id, login_id, owner_id) VALUES (?, ?, ?)");
		$userInfoQuery->execute(array($userId, "", $ownerId));

		$db = null;
			
		setcookie("aga_userid", $userId, time() + 315360000, "/");

		$_SESSION["user_id"] = $userInfo[0][$userId];
		$_SESSION["owner_id"] = $userInfo[0][$ownerId];
	}

?>