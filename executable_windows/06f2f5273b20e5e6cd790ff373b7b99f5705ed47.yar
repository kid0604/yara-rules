rule HKTL_CobaltStrike_Beacon_XOR_Strings
{
	meta:
		author = "Elastic"
		description = "Identifies XOR'd strings used in Cobalt Strike Beacon DLL"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		date = "2021-03-16"
		xor_s1 = "%02d/%02d/%02d %02d:%02d:%02d"
		xor_s2 = "Started service %s on %s"
		xor_s3 = "%s as %s\\%s: %d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x01-0xff)
		$s2 = "Started service %s on %s" xor(0x01-0xff)
		$s3 = "%s as %s\\%s: %d" xor(0x01-0xff)
		$fp1 = "MalwareRemovalTool"

	condition:
		2 of ($s*) and not 1 of ($fp*)
}
