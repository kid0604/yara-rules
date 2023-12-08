rule CN_Honker_Webshell_udf_udf
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file udf.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "df63372ccab190f2f1d852f709f6b97a8d9d22b9"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<?php // Source  My : Meiam  " fullword ascii
		$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii

	condition:
		filesize <430KB and all of them
}
