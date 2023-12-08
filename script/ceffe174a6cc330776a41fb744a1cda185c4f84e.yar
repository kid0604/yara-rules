rule SUSP_IIS_Config_ProxyShell_Artifacts
{
	meta:
		description = "Detects suspicious virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		date = "2021-08-25"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$s1 = " physicalPath=\"C:\\ProgramData\\" ascii

	condition:
		filesize <500KB and all of ($a*) and 1 of ($s*)
}
