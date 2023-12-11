import "pe"

rule VcasmProtector1112vcasm
{
	meta:
		author = "malware-lu"
		description = "Detects Vcasm Protector 1112vcasm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
		$a0 at pe.entry_point
}
