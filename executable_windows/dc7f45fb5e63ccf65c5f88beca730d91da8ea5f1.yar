import "math"
import "pe"

rule PureBasic_alt_1 : Neil Hodgson
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "Detects PureBasic compiled executables with specific characteristics"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 55 8B EC 6A 00 68 00 10 00 00 6A ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 10 00 00 00 A1 ?? ?? ?? ?? 50 6A ?? 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5D C3 CC CC CC CC CC CC CC CC CC }
		$c1 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }
		$aa0 = "\x00MSVCRT.dll\x00" ascii
		$aa1 = "\x00CRTDLL.dll\x00" ascii

	condition:
		( for any of ($c0,$c1) : ($ at pe.entry_point)) and ( any of ($aa*)) and ((pe.linker_version.major==2) and (pe.linker_version.minor==50))
}