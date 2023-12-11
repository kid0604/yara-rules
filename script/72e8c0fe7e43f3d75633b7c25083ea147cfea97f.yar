rule CN_Honker_Webshell_PHP_php2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf12e1d741075cd1bd324a143ec26c732a241dea"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
		$s2 = "<?php // Black" fullword ascii

	condition:
		filesize <12KB and all of them
}
