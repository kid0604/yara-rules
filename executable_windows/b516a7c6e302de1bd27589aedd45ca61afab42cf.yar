rule Sniffer_analyzer_SSClone_1210_full_version
{
	meta:
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
		$s1 = "GetConnectString" fullword ascii
		$s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
		$s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3580KB and all of them
}
