import "pe"

rule VxVirusConstructorIVPbased
{
	meta:
		author = "malware-lu"
		description = "Detects VxVirus Constructor IV based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [2] E8 [2] 5D [5] 81 ED [6] E8 [2] 81 FC [4] 8D [3] BF [2] 57 A4 A5 }

	condition:
		$a0 at pe.entry_point
}
