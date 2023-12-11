rule APT_UA_Hermetic_Wiper_Scheduled_Task_Feb22_1
{
	meta:
		description = "Detects scheduled task pattern found in Hermetic Wiper malware related intrusions"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
		date = "2022-02-25"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "<Task version=" ascii wide
		$sa1 = "CSIDL_SYSTEM_DRIVE\\temp" ascii wide
		$sa2 = "postgresql.exe 1> \\\\127.0.0.1\\ADMIN$" ascii wide
		$sa3 = "cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE" ascii wide

	condition:
		$a0 and 1 of ($s*)
}
