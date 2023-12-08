rule LiuDoor_Malware_1
{
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "deed6e2a31349253143d4069613905e1dfc3ad4589f6987388de13e33ac187fc"
		hash2 = "4575e7fc8f156d1d499aab5064a4832953cd43795574b4c7b9165cdc92993ce5"
		hash3 = "ad1a507709c75fe93708ce9ca1227c5fefa812997ed9104ff9adfec62a3ec2bb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "svchostdllserver.dll" fullword ascii
		$s2 = "SvcHostDLL: RegisterServiceCtrlHandler %S failed" fullword ascii
		$s3 = "\\nbtstat.exe" fullword ascii
		$s4 = "DataVersionEx" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
