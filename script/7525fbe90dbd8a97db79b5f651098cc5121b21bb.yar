rule EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Zach Stanford - @svch0st, Florian Roth"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/#scan-log"
		reference_2 = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		date = "2021-03-10"
		modified = "2021-03-15"
		score = 65
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "ServerInfo~" ascii wide
		$sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide
		$s1 = "/ecp/auth/w.js" ascii wide
		$s2 = "/owa/auth/w.js" ascii wide
		$s3 = "/owa/auth/x.js" ascii wide
		$s4 = "/ecp/main.css" ascii wide
		$s5 = "/ecp/default.flt" ascii wide
		$s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide

	condition:
		$x1 and 1 of ($s*)
}
