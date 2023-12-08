rule APT_IIS_Config_ProxyShell_Artifacts
{
	meta:
		description = "Detects virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		date = "2021-08-25"
		score = 90
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$sa1 = " physicalPath=\"C:\\ProgramData\\COM" ascii
		$sa2 = " physicalPath=\"C:\\ProgramData\\WHO" ascii
		$sa3 = " physicalPath=\"C:\\ProgramData\\ZING" ascii
		$sa4 = " physicalPath=\"C:\\ProgramData\\ZOO" ascii
		$sa5 = " physicalPath=\"C:\\ProgramData\\XYZ" ascii
		$sa6 = " physicalPath=\"C:\\ProgramData\\AUX" ascii
		$sa7 = " physicalPath=\"C:\\ProgramData\\CON\\" ascii
		$sb1 = " physicalPath=\"C:\\Users\\All Users\\" ascii

	condition:
		filesize <500KB and all of ($a*) and 1 of ($s*)
}
