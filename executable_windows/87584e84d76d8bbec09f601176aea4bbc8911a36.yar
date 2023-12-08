import "pe"

rule MetrowerksCodeWarriorDLLv20
{
	meta:
		author = "malware-lu"
		description = "Detects Metrowerks CodeWarrior DLL v2.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 [4] 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }

	condition:
		$a0
}
