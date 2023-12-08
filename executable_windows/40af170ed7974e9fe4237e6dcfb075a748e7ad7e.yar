import "pe"

rule ExeShieldProtectorV36wwwexeshieldcom
{
	meta:
		author = "malware-lu"
		description = "Detects ExeShield Protector v3.6 from www.exeshield.com"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }

	condition:
		$a0 at pe.entry_point
}
