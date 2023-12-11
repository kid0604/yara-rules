import "pe"

rule APatchGUIv11
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of APatchGUIv11 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF }

	condition:
		$a0 at pe.entry_point
}
