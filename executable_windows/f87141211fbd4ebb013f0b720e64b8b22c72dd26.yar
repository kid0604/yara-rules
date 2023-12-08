rule Methodology_Suspicious_Shortcut_WebDAV
{
	meta:
		author = "@itsreallynick (Nick Carr)"
		reference = "https://twitter.com/cglyer/status/1176243536754282497"
		description = "Detects possible shortcut usage for .URL persistence"
		score = 50
		date = "27.09.2019"
		os = "windows"
		filetype = "executable"

	strings:
		$file1 = /[\x0a\x0d](IconFile|(Base|)URL)\s*=\s*\/\/[A-Za-z0-9]/
		$url_clsid = "[{000214A0-0000-0000-C000-000000000046}]"
		$url_explicit = "[InternetShortcut]" nocase

	condition:
		any of ($url*) and any of ($file*) and uint16(0)!=0x5A4D and uint32(0)!=0x464c457f and uint32(0)!=0xBEBAFECA and uint32(0)!=0xFEEDFACE and uint32(0)!=0xFEEDFACF and uint32(0)!=0xCEFAEDFE and filesize <30KB
}
