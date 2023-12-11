import "pe"

rule AsCryptv01SToRM4
{
	meta:
		author = "malware-lu"
		description = "Detects AsCryptv01SToRM4 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 E2 }

	condition:
		$a0
}
