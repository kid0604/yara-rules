import "pe"

rule PseudoSigner02BorlandDelphiSetupModuleAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi setup module PseudoSigner02BorlandDelphi"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
