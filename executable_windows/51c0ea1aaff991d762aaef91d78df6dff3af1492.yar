import "pe"

rule UPXHiT001DJSiba
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the UPX packer in DJ Siba malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }

	condition:
		$a0
}
