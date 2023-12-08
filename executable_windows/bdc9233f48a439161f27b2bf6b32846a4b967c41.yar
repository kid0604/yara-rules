import "pe"

rule aPackv098bDSESnotsaved
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of aPackv098bDSESnotsaved malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8C CB BA [2] 03 DA FC 33 F6 33 FF 4B 8E DB 8D [3] 8E C0 B9 [2] F3 A5 4A 75 }

	condition:
		$a0
}
