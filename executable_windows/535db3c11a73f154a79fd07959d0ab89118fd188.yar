rule INDICATOR_TOOL_PRV_AdvancedRun
{
	meta:
		author = "ditekSHen"
		description = "Detects NirSoft AdvancedRun privialge escalation tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RunAsProcessName" fullword wide
		$s2 = "Process ID/Name:" fullword wide
		$s3 = "swinsta.dll" fullword wide
		$s4 = "User of the selected process0Child of selected process (Using code injection) Specified user name and password" fullword wide
		$s5 = "\"Current User - Allow UAC Elevation$Current User - Without UAC Elevation#Administrator (Force UAC Elevation)" fullword wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
