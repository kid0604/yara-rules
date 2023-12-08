rule Dos_fp
{
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s2 = "FPipe.exe" fullword wide
		$s3 = "http://www.foundstone.com" fullword ascii
		$s4 = "%s %s port %d. Address is already in use" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <65KB and all of them
}
