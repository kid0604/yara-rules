rule Linux_Exploit_Pulse_246e6f31
{
	meta:
		author = "Elastic Security"
		id = "246e6f31-fcfb-474e-9709-a5d7ea6586fd"
		fingerprint = "e98007a2fa62576e1847cf350283f60f1e4e49585574601ab44b304f391240db"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Pulse"
		reference_sample = "c29cb4c2d83127cf4731573a7fac531f90f27799857f5e250b9f71362108f559"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Pulse"
		filetype = "executable"

	strings:
		$a = { 48 8D 45 F8 48 89 45 F8 48 8B 45 F8 48 25 00 E0 FF FF 48 8B 00 48 89 }

	condition:
		all of them
}
