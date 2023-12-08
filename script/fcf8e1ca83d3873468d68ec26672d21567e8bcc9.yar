rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1
{
	meta:
		description = "Detects HAFNIUM SecChecker webshell"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/markus_neis/status/1367794681237667840"
		date = "2021-03-05"
		hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
		$x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword

	condition:
		uint16(0)==0x253c and filesize <1KB and 1 of them or 2 of them
}
