import "pe"

rule Oilrig_IntelSecurityManager_alt_1
{
	meta:
		description = "Detects OilRig malware"
		author = "Eyal Sela"
		reference = "Internal Research"
		date = "2018-01-19"
		os = "windows"
		filetype = "script"

	strings:
		$one1 = "srvResesponded" ascii wide fullword
		$one2 = "InetlSecurityAssistManager" ascii wide fullword
		$one3 = "srvCheckresponded" ascii wide fullword
		$one4 = "IntelSecurityManager" ascii wide
		$one5 = "msoffice365cdn.com" ascii wide
		$one6 = "\\tmpCa.vbs" ascii wide
		$one7 = "AAZFinish" ascii wide fullword
		$one8 = "AAZUploaded" ascii wide fullword
		$one9 = "ABZFinish" ascii wide fullword
		$one10 = "\\tmpCa.vbs" ascii wide

	condition:
		filesize <300KB and any of them
}
