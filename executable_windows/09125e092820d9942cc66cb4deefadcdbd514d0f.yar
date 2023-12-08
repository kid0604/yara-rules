import "pe"

rule NSISInstallerNullSoft
{
	meta:
		author = "malware-lu"
		description = "Detects NSIS (Nullsoft Scriptable Install System) installer executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 [4] C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 [4] 68 [4] A3 [4] E8 [4] BE }

	condition:
		$a0 at pe.entry_point
}
