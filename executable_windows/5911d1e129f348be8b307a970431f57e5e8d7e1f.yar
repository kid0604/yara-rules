rule LiuDoor_Malware_2
{
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "f3fb68b21490ded2ae7327271d3412fbbf9d705c8003a195a705c47c98b43800"
		hash2 = "e42b8385e1aecd89a94a740a2c7cd5ef157b091fabd52cd6f86e47534ca2863e"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "svchostdllserver.dll" fullword ascii
		$s1 = "Lpykh~mzCCRv|mplpykCCHvq{phlCC\\jmmzqkIzmlvpqCC" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
