import "pe"

rule VterminalV10XLeiPeng
{
	meta:
		author = "malware-lu"
		description = "Detects VterminalV10XLeiPeng malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 05 [4] 9C 50 C2 04 00 }

	condition:
		$a0 at pe.entry_point
}
