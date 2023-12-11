rule ShellCrew_StreamEx_1_msi
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
		date = "2017-02-10"
		hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "msi.dll.eng" fullword wide
		$s2 = "ahinovx" fullword ascii
		$s3 = "jkpsxy47CDEMNSTYbhinqrwx56" fullword ascii
		$s4 = "PVYdejmrsy12" fullword ascii
		$s6 = "FLMTUZaijkpsxy45CD" fullword ascii
		$s7 = "afhopqvw34ABIJOPTYZehmo" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 3 of them )
}
