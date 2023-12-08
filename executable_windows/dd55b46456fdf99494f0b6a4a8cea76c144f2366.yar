rule Detect_Stealc_Stealer
{
	meta:
		description = "Stealc Info Stealer"
		author = "@FarghlyMal"
		hash = "sha256,1E09D04C793205661D88D6993CB3E0EF5E5A37A8660F504C1D36B0D8562E63A2"
		Date = "8/11/2023"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "block"
		$s2 = "Network Info:"
		$s3 = "- IP: IP?"
		$s4 = "- Country: ISO?"
		$hex_value = {74 03 75 01 b8 e8}
		$hex_value2 = {8B 48 F8 83 C0 F0 C7 00 01 00 00 00 85 C9 74 0A 83 39 00}

	condition:
		uint16(0)==0x5A4D and all of ($s*) and all of ($hex_value*)
}
