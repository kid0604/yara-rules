import "pe"

rule APT28_SourFace_Malware2
{
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		super_rule = 1
		hash0 = "367d40465fd1633c435b966fa9b289188aa444bc"
		hash1 = "cf3220c867b81949d1ce2b36446642de7894c6dc"
		hash2 = "ed48ef531d96e8c7360701da1c57e2ff13f12405"
		hash3 = "682e49efa6d2549147a21993d64291bfa40d815a"
		hash4 = "a8551397e1f1a2c0148e6eadcb56fa35ee6009ca"
		hash5 = "f5b3e98c6b5d65807da66d50bd5730d35692174d"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "coreshell.dll" fullword ascii
		$s1 = "Applicate" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <550KB and all of them
}
