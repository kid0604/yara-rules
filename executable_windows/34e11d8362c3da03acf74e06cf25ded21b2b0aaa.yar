import "pe"

rule APT28_SourFace_Malware1
{
	meta:
		description = "Detects Malware from APT28 incident - SOURFACE is a downloader that obtains a second-stage backdoor from a C2 server."
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html"
		date = "2015-06-01"
		hash1 = "e2450dffa675c61aa43077b25b12851a910eeeb6"
		hash2 = "d9c53adce8c35ec3b1e015ec8011078902e6800b"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "coreshell.dll" fullword wide
		$s1 = "Core Shell Runtime Service" fullword wide
		$s2 = "\\chkdbg.log" wide

	condition:
		uint16(0)==0x5a4d and filesize <62KB and all of them
}
