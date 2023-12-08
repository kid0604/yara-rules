import "pe"

rule y0dasCrypterv12
{
	meta:
		author = "malware-lu"
		description = "Detects y0dasCrypter v1.2"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC [48] AA E2 CC }

	condition:
		$a0 at pe.entry_point
}
