rule SUSP_IIS_Config_VirtualDir
{
	meta:
		description = "Detects suspicious virtual directory configured in IIS pointing to a User folder"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		date = "2021-08-25"
		modified = "2022-09-17"
		score = 60
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$s2 = " physicalPath=\"C:\\Users\\" ascii
		$fp1 = "Microsoft.Web.Administration" wide
		$fp2 = "<virtualDirectory path=\"/\" physicalPath=\"C:\\Users\\admin\\"

	condition:
		filesize <500KB and all of ($a*) and 1 of ($s*) and not 1 of ($fp*)
}
