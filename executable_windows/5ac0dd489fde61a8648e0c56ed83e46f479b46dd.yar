import "pe"

rule AsCryptv01SToRM3
{
	meta:
		author = "malware-lu"
		description = "Detects AsCryptv01SToRM3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 51 [3] 01 00 00 00 83 [2] E2 }

	condition:
		$a0
}
