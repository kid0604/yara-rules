rule Gafgyt_Botnet_bash : MALW
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-25"
		version = "1.0"
		MD5 = "c8d58acfe524a09d4df7ffbe4a43c429"
		SHA1 = "b41fefa8470f3b3657594af18d2ea4f6ac4d567f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "PONG!"
		$s2 = "GETLOCALIP"
		$s3 = "HTTPFLOOD"
		$s4 = "LUCKYLILDUDE"

	condition:
		$s1 and $s2 and $s3 and $s4
}
