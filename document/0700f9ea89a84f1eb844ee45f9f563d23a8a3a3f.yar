rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_1 : Windows CVE
{
	meta:
		author = "Florian Roth (Nextron Systems)"
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		date = "2021-09-18"
		score = 65
		hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E"
		hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69"
		os = "windows"
		filetype = "document"

	strings:
		$h1 = "<?xml " ascii wide
		$xml_e = "Target=\"&#" ascii wide
		$xml_mode_1 = "TargetMode=\"&#" ascii wide

	condition:
		filesize <500KB and $h1 and 1 of ($xml*)
}
