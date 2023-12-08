rule Hawkeye
{
	meta:
		description = "detect HawkEye in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		os = "windows"
		filetype = "executable"

	strings:
		$hawkstr1 = "HawkEye Keylogger" wide
		$hawkstr2 = "Dear HawkEye Customers!" wide
		$hawkstr3 = "HawkEye Logger Details:" wide

	condition:
		all of them
}
