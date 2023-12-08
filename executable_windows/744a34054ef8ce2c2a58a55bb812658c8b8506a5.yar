rule COZY_FANCY_BEAR_pagemgr_Hunt
{
	meta:
		description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "pagemgr.exe" wide fullword

	condition:
		uint16(0)==0x5a4d and 1 of them
}
