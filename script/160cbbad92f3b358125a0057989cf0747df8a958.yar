rule DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3
{
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
		$s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii

	condition:
		( uint16(0)==0x3c0a and filesize <300KB and all of them )
}
