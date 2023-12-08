rule Codoso_PGV_PVID_4_alt_1
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		author = "Florian Roth"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash3 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash4 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash5 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "dropper, Version 1.0" fullword wide
		$x2 = "dropper" fullword wide
		$x3 = "DROPPER" fullword wide
		$x4 = "About dropper" fullword wide
		$s1 = "Microsoft Windows Manager Utility" fullword wide
		$s2 = "SYSTEM\\CurrentControlSet\\Services\\" fullword ascii
		$s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" fullword ascii
		$s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
		$s5 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></supportedOS>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 1 of ($x*) and 2 of ($s*)
}
