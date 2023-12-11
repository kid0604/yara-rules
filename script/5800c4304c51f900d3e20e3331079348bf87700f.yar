rule webshell_php_2
{
	meta:
		description = "Web Shell - file 2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "267c37c3a285a84f541066fc5b3c1747"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword

	condition:
		all of them
}
