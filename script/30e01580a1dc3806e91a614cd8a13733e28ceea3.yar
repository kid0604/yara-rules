rule Methodology_Suspicious_Shortcut_Local_URL
{
	meta:
		author = "@itsreallynick (Nick Carr), @QW5kcmV3 (Andrew Thompson)"
		description = "Detects local script usage for .URL persistence"
		reference = "https://twitter.com/cglyer/status/1176184798248919044"
		score = 50
		date = "27.09.2019"
		os = "windows"
		filetype = "script"

	strings:
		$file = "URL=file:///" nocase
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		$file and any of ($url*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
