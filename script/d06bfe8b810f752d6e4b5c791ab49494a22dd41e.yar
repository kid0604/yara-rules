rule webshell_php_h6ss
{
	meta:
		description = "Web Shell - file h6ss.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "272dde9a4a7265d6c139287560328cd5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php eval(gzuncompress(base64_decode(\""

	condition:
		all of them
}
