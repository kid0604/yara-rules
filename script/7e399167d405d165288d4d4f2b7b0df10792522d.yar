rule APT_KE3CHANG_TMPFILE : APT KE3CHANG TMPFILE
{
	meta:
		description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
		author = "Markus Neis, Swisscom"
		reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
		date = "2020-06-18"
		hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"
		os = "windows"
		filetype = "script"

	strings:
		$pps1 = "PSParentPath             : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$pps2 = "PSPath                   : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$psp1 = ": Microsoft.PowerShell.Core\\Registry" ascii
		$s4 = "PSChildName  : PhishingFilter" fullword ascii
		$s1 = "DisableFirstRunCustomize : 2" fullword ascii
		$s7 = "PSChildName  : 3" fullword ascii
		$s8 = "2500         : 3" fullword ascii

	condition:
		uint16(0)==0x5350 and filesize <1KB and $psp1 and 1 of ($pps*) and 1 of ($s*)
}
