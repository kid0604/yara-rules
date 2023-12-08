import "pe"

rule APT_Winnti_MAL_Dec19_5
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		date = "2019-12-06"
		score = 75
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "-k netsvcs" ascii
		$a2 = "svchost.exe" ascii fullword
		$a3 = "%SystemRoot%\\System32\\ntoskrnl.exe" ascii
		$a4 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii
		$a5 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii
		$a6 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii
		$a7 = "cmd.exe" wide
		$a8 = ",XML" wide
		$a9 = "\\rundll32.exe" wide
		$a10 = "\\conhost.exe" wide
		$a11 = "\\cmd.exe" wide
		$a12 = "NtQueryInformationProcess" ascii
		$a13 = "Detours!" ascii fullword
		$a14 = "Loading modified build of detours library designed for MPC-HC player (http://sourceforge.net/projects/mpc-hc/)" ascii
		$a15 = "CONOUT$" wide fullword
		$a16 = { C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }

	condition:
		(12 of ($a*))
}
