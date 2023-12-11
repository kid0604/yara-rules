import "pe"

rule DingBoysPElockPhantasmv10v11
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of DingBoysPElock Phantasm v1.0 and v1.1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

	condition:
		$a0 at pe.entry_point
}
