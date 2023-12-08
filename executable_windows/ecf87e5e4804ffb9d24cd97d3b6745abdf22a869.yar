import "pe"

rule INDICATOR_EXE_Packed_SilentInstallBuilder
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Silent Install Builder"
		snort2_sid = "930070-930072"
		snort3_sid = "930025"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Users\\Operations\\Source\\Workspaces\\Sib\\Sibl\\Release\\Sibuia.pdb" fullword ascii
		$s2 = "->mb!Silent Install Builder Demo Package." fullword wide

	condition:
		uint16(0)==0x5a4d and 1 of them
}
