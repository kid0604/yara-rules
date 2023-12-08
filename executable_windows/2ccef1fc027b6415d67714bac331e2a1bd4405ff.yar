import "pe"

rule WARNINGTROJANXiaoHui
{
	meta:
		author = "malware-lu"
		description = "Detects the WARNINGTROJANXiaoHui malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00 }

	condition:
		$a0 at pe.entry_point
}
