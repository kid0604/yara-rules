rule Emdivi_SFX
{
	meta:
		description = "Detects Emdivi malware in SFX Archive"
		author = "Florian Roth (Nextron Systems) @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		score = 70
		hash1 = "7a3c81b2b3c14b9cd913692347019887b607c54152b348d6d3ccd3ecfd406196"
		hash2 = "8c3df4e4549db3ce57fc1f7b1b2dfeedb7ba079f654861ca0b608cbfa1df0f6b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Setup=unsecess.exe" fullword ascii
		$x2 = "Setup=leassnp.exe" fullword ascii
		$s1 = "&Enter password for the encrypted file:" fullword wide
		$s2 = ";The comment below contains SFX script commands" fullword ascii
		$s3 = "Path=%temp%" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <740KB and (1 of ($x*) and all of ($s*))
}
