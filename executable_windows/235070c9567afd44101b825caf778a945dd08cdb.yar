import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_ReflectiveLoader
{
	meta:
		description = "detects Reflective DLL injection artifacts"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "_ReflectiveLoader@" ascii wide
		$s2 = "ReflectiveLoader@" ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of them or (pe.exports("ReflectiveLoader@4") or pe.exports("_ReflectiveLoader@4") or pe.exports("ReflectiveLoader")))
}
