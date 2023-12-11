rule heistenberg_pos
{
	meta:
		author = "@patrickrolsen"
		reference = "POS Malware"
		description = "Detects Heistenberg POS malware"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "KARTOXA"
		$s2 = "dmpz.log"
		$s3 = "/api/process.php?xy="
		$s4 = "User-Agent: PCICompliant"
		$s6 = "%s:*:Enabled:%s"

	condition:
		uint16(0)==0x5A4D and 3 of ($s*)
}
