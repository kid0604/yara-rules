rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz
{
	meta:
		description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
		$s11 = "directory... Trust me - it works :-) */" fullword
		$s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
		$s16 = "} else if ($command == 'ls') {" fullword

	condition:
		3 of them
}
