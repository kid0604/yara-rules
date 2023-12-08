rule Codoso_PGV_PVID_3
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "126fbdcfed1dfb31865d4b18db2fb963f49df838bf66922fea0c37e06666aee1"
		hash2 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash3 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
		hash4 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
		hash5 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash6 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Copyright (C) Microsoft Corporation.  All rights reserved.(C) 2012" fullword wide

	condition:
		$x1
}
