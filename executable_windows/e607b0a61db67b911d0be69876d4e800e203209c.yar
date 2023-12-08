rule TSC_Loader
{
	meta:
		description = "detect TSCookie Loader in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		os = "windows"
		filetype = "executable"

	strings:
		$v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
		$b1 = { 68 78 0B 00 00 }

	condition:
		all of them
}
