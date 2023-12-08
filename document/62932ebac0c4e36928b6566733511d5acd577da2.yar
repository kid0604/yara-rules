rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_2 : Windows CVE
{
	meta:
		author = "Florian Roth (Nextron Systems)"
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		date = "2021-09-18"
		score = 65
		os = "windows"
		filetype = "document"

	strings:
		$h1 = "<?xml " ascii wide
		$a1 = "Target" ascii wide
		$a2 = "TargetMode" ascii wide
		$xml_e = "&#x0000" ascii wide

	condition:
		filesize <500KB and all of them
}
