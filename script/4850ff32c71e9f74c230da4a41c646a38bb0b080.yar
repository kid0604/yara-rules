rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY
{
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "40a1f840111996ff7200d18968e42cfe"
		hash3 = "0712e3dc262b4e1f98ed25760b206836"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "http://www.4ngel.net" fullword
		$s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
		$s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
		$s9 = "Codz by Angel" fullword

	condition:
		2 of them
}
