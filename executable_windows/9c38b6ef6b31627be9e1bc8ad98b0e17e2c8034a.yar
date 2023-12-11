import "pe"

rule MALWARE_Win_PELoader_INF
{
	meta:
		author = "ditekSHen"
		description = "Detects PE loader / injector. Potentical HCrypt. Observed Gorgon TTPs"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Managament.inf" fullword ascii
		$x2 = "rOnAlDo" fullword ascii
		$x3 = "untimeResourceSet" fullword ascii
		$x4 = "3System.Resources.Tools.StronglyTypedResourceBuilder" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
