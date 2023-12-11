rule CN_Honker_Webshell_phpwebbackup
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c788cb280b7ad0429313837082fe84e9a49efab6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii

	condition:
		uint16(0)==0x3f3c and filesize <67KB and all of them
}
