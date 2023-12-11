rule webshell_php_sh_server
{
	meta:
		description = "Web Shell - file server.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 50
		hash = "d87b019e74064aa90e2bb143e5e16cfa"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "eval(getenv('HTTP_CODE'));" fullword

	condition:
		all of them
}
