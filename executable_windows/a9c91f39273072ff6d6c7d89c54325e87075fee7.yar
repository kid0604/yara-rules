import "pe"

rule VcasmProtectorV1Xvcasm
{
	meta:
		author = "malware-lu"
		description = "Detects Vcasm Protector V1Xvcasm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
		$a0 at pe.entry_point
}
