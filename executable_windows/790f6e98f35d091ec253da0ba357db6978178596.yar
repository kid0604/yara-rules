rule WildNeutron_Sample_3
{
	meta:
		description = "Wild Neutron APT Sample Rule - file c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "c2c761cde3175f6e40ed934f2e82c76602c81e2128187bab61793ddb3bc686d0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "178.162.197.9" fullword ascii
		$x2 = "\"http://fw.ddosprotected.eu:80 /opts resolv=drfx.chickenkiller.com\"" fullword wide
		$s1 = "LiveUpdater.exe" fullword wide
		$s2 = "id-at-postalAddress" fullword ascii
		$s3 = "%d -> %d (default)" fullword wide
		$s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s5 = "id-at-serialNumber" fullword ascii
		$s6 = "ECDSA with SHA256" fullword ascii
		$s7 = "Acer LiveUpdater" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2020KB and (1 of ($x*) or all of ($s*))
}
