import "pe"

rule MALWARE_Win_Bulz01
{
	meta:
		author = "ditekSHen"
		description = "Detects trojan loader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DisableTrivet.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and all of ($s*) and (pe.exports("Ordinal") or pe.exports("Chechako") or pe.exports("Originator") or pe.exports("Repressions"))
}
