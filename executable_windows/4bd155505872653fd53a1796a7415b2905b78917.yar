rule HKTL_CobaltStrike_Beacon_Strings
{
	meta:
		author = "Elastic"
		description = "Identifies strings used in Cobalt Strike Beacon DLL"
		reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
		date = "2021-03-16"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%02d/%02d/%02d %02d:%02d:%02d"
		$s2 = "Started service %s on %s"
		$s3 = "%s as %s\\%s: %d"

	condition:
		2 of them
}
