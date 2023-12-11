rule kappfree_2
{
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}
