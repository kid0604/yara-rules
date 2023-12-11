import "pe"

rule APT_FIN7_Sample_Aug18_2
{
	meta:
		description = "Detects FIN7 malware sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "1513c7630c981e4b1d0d5a55809166721df4f87bb0fac2d2b8ff6afae187f01d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Description: C:\\Users\\oleg\\Desktop\\" wide
		$x2 = "/*|*| *  Copyright 2016 Microsoft, Industries.|*| *  All rights reserved.|*|" ascii
		$x3 = "32, 40, 102, 105, 108, 101, 95, 112, 97, 116, 104, 41, 41, 32" ascii
		$x4 = "83, 108, 101, 101, 112, 40, 51, 48, 48, 48, 41, 59, 102, 115" ascii
		$x5 = "80, 80, 68, 65, 84, 65, 37, 34, 41, 44, 115, 104, 101, 108, 108" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <2000KB and 1 of them
}
