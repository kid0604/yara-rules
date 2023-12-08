rule DUBrute_DUBrute
{
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s4 = "UBrute.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1020KB and all of them
}
