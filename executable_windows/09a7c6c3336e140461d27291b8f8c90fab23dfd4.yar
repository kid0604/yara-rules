rule INDICATOR_TOOL_PWS_Blackbone
{
	meta:
		author = "ditekSHen"
		description = "detects Blackbone password dumping tool on Windows 7-10 operating system."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "BlackBone: %s: " ascii
		$s2 = "\\BlackBoneDrv\\" ascii
		$s3 = "\\DosDevices\\BlackBone" fullword wide
		$s4 = "\\Temp\\BBImage.manifest" wide
		$s5 = "\\Device\\BlackBone" fullword wide
		$s6 = "BBExecuteInNewThread" fullword ascii
		$s7 = "BBHideVAD" fullword ascii
		$s8 = "BBInjectDll" fullword ascii
		$s9 = "ntoskrnl.exe" fullword ascii
		$s10 = "WDKTestCert Ton," ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
