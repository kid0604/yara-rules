rule ThreatGroup3390_Strings
{
	meta:
		description = "Threat Group 3390 APT - Strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\"cmd\" /c cd /d \"c:\\Windows\\Temp\\\"&copy" ascii
		$s2 = "svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014"
		$s3 = "ren *.rar *.zip" fullword ascii
		$s4 = "c:\\temp\\ipcan.exe" fullword ascii
		$s5 = "<%eval(Request.Item(\"admin-na-google123!@#" ascii

	condition:
		1 of them and filesize <30KB
}
