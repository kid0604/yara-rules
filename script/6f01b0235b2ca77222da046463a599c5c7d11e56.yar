import "pe"

rule APT_Thrip_Sample_Jun18_8
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "0f2d09b1ad0694f9e71eeebec5b2d137665375bf1e76cb4ae4d7f20487394ed3"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "$.oS.Run('cmd.exe /c '+a+'" fullword ascii
		$x2 = "new $._x('WScript.Shell');" ascii
		$x3 = ".ExpandEnvironmentStrings('%Temp%')+unescape('" ascii

	condition:
		filesize <10KB and 1 of ($x*)
}
