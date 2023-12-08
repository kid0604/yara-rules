rule KA_uShell
{
	meta:
		description = "Webshells Auto-generated - file KA_uShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "685f5d4f7f6751eaefc2695071569aab"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
		$s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"

	condition:
		all of them
}
