rule ipsearcher
{
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <140KB and all of them
}
