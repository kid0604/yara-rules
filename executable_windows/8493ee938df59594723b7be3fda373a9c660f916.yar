import "pe"

rule LY_WGKXwwwszleyucom
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of MyFun malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4D 79 46 75 6E 00 62 73 }

	condition:
		$a0
}
