import "pe"

rule Cryptic20Tughack
{
	meta:
		author = "malware-lu"
		description = "Detects Cryptic20Tughack malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 00 00 40 00 BB [3] 00 B9 00 10 00 00 BA [3] 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3 }

	condition:
		$a0 at pe.entry_point
}
