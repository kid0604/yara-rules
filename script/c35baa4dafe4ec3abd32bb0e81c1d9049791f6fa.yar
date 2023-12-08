rule webshell_php_404
{
	meta:
		description = "Web Shell - file 404.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ced050df5ca42064056a7ad610a191b3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$pass = md5(md5(md5($pass)));" fullword

	condition:
		all of them
}
