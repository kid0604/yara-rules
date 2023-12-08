import "pe"

rule PseudoSigner02BorlandDelphiDLLAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi DLL files signed with PseudoSigner02 and compiled with Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}
