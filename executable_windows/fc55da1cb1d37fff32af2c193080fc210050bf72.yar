import "pe"

rule ReflectiveLoader_alt_1
{
	meta:
		description = "Detects a unspecified hack tool, crack or malware using a reflective loader - no hard match - further investigation recommended"
		reference = "Internal Research"
		score = 70
		date = "2017-07-17"
		modified = "2021-03-15"
		author = "Florian Roth (Nextron Systems)"
		nodeepdive = 1
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ReflectiveLoader" fullword ascii
		$x2 = "ReflectivLoader.dll" fullword ascii
		$x3 = "?ReflectiveLoader@@" ascii
		$x4 = "reflective_dll.x64.dll" fullword ascii
		$x5 = "reflective_dll.dll" fullword ascii
		$fp1 = "Sentinel Labs, Inc." wide
		$fp2 = "Panda Security, S.L." wide ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or pe.exports("ReflectiveLoader") or pe.exports("_ReflectiveLoader@4") or pe.exports("?ReflectiveLoader@@YGKPAX@Z")) and not 1 of ($fp*)
}
