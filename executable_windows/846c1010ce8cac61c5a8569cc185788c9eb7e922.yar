import "pe"

rule WWPACKv302v302av304Relocationspack
{
	meta:
		author = "malware-lu"
		description = "Detects the WWPACKv302v302av304Relocationspack malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [2] BF [2] B9 [2] 8C CD 81 ED [2] 8B DD 81 EB [2] 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }

	condition:
		$a0 at pe.entry_point
}
