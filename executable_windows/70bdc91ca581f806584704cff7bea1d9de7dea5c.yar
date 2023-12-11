import "pe"

rule DJoinv07publicxorencryptiondrmist
{
	meta:
		author = "malware-lu"
		description = "Detects DJoinv07 public XOR encryption DRMIST malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C6 05 [2] 40 00 00 [8] 00 [4] 00 [5] 00 }

	condition:
		$a0 at pe.entry_point
}
