rule WebShell_PHP_Web_Kit_v3
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		reference = "https://github.com/wordfence/grizzly"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2016/01/01"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php = "<?php $"
		$php2 = "@assert(base64_decode($_REQUEST["
		$s1 = "(str_replace(\"\\n\", '', '"
		$s2 = "(strrev($" ascii
		$s3 = "de'.'code';" ascii

	condition:
		(( uint32(0)==0x68703f3c and $php at 0) or $php2) and filesize >8KB and filesize <100KB and all of ($s*)
}
