rule pstgdump
{
	meta:
		author = "@patrickrolsen"
		reference = "pstgdump"
		description = "Detects the presence of pstgdump tool used for dumping password hashes from Outlook PST files"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fgdump\\pstgdump"
		$s2 = "pstgdump"
		$s3 = "Outlook"

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}
