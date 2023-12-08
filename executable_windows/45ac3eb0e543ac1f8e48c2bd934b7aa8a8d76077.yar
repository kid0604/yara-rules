import "pe"

rule xtreme_rat_0
{
	meta:
		maltype = "Xtreme RAT"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
		description = "Detects Xtreme RAT activity based on specific Windows security event logs"
		os = "windows"
		filetype = "executable"

	strings:
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "5156"
		$data = "windows\\system32\\sethc.exe"
		$type1 = "Microsoft-Windows-Security-Auditing"
		$eventid1 = "4688"
		$data1 = "AppData\\Local\\Temp\\Microsoft Word.exe"

	condition:
		all of them
}
