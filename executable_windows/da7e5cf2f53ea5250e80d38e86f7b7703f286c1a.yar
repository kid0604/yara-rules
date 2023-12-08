rule misc_pos
{
	meta:
		author = "@patrickrolsen"
		reference = "POS Malware"
		description = "Detects POS malware related strings"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "KAPTOXA"
		$s2 = "cmd /c net start %s"
		$s3 = "pid:"
		$s4 = "%ADD%"
		$s5 = "COMSPEC"
		$s6 = "KARTOXA"

	condition:
		uint16(0)==0x5A4D and 3 of ($s*)
}
