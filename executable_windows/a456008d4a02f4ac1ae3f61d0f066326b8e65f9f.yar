import "pe"

rule VxInvoluntary1349
{
	meta:
		author = "malware-lu"
		description = "Detects VxInvoluntary1349 malware based on specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [2] B9 [2] 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC [2] AD ?? 33 C2 AB }

	condition:
		$a0 at pe.entry_point
}
