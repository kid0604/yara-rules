import "pe"
import "math"

rule borland_delphi_dll
{
	meta:
		author = "_pusher_"
		description = "Borland Delphi DLL"
		date = "2015-08"
		version = "0.1"
		info = "one is at entrypoint"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
		$c1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }

	condition:
		any of them
}
