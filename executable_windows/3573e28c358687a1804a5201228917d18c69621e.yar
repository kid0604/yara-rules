rule WildNeutron_Sample_5
{
	meta:
		description = "Wild Neutron APT Sample Rule - file 1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "1604e36ccef5fa221b101d7f043ad7f856b84bf1a80774aa33d91c2a9a226206"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "LiveUpdater.exe" fullword wide
		$s1 = "id-at-postalAddress" fullword ascii
		$s2 = "%d -> %d (default)" fullword wide
		$s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s4 = "sha-1WithRSAEncryption" fullword ascii
		$s5 = "Postal code" fullword ascii
		$s6 = "id-ce-keyUsage" fullword ascii
		$s7 = "Key Usage" fullword ascii
		$s8 = "TLS-RSA-WITH-3DES-EDE-CBC-SHA" fullword ascii
		$s9 = "%02d.%04d.%s" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
