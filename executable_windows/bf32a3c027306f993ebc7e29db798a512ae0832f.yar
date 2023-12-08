import "pe"

rule PKLITEv100c1
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PKLITEv100c1 in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E 8C 1E [2] 8B 1E [2] 8C DA 81 C2 [2] 3B DA 72 ?? 81 EB [2] 83 EB ?? FA 8E D3 BC [2] FB FD BE [2] 8B FE }

	condition:
		$a0 at pe.entry_point
}
