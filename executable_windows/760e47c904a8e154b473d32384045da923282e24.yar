import "pe"
import "math"

rule PureBasicDLL_alt_1 : Neil Hodgson
{
	meta:
		author = "malware-lu"
		description = "Detects PureBasic DLL alternative 1 by Neil Hodgson"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

	condition:
		$a0 at pe.entry_point
}
