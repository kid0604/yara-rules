rule webshell_wsb_idc
{
	meta:
		description = "Web Shell - file idc.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "7c5b1b30196c51f1accbffb80296395f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
		$s3 = "{eval($_GET['idc']);}" fullword

	condition:
		1 of them
}
