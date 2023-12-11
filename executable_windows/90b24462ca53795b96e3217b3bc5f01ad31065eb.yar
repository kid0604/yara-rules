rule INDICATOR_TOOL_EXP_SharpPrintNightmare
{
	meta:
		author = "ditekSHen"
		description = "Detect SharpPrintNightmare"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RevertToSelf() Error:" wide
		$s2 = "NeverGonnaGiveYou" wide
		$s3 = "\\Amd64\\UNIDRV.DLL" wide
		$s4 = ":\\Windows\\System32\\DriverStore\\FileRepository\\" wide
		$s5 = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}" wide
		$s6 = "\\SharpPrintNightmare\\" ascii
		$s7 = { 4e 61 6d 65 09 46 75 6c 6c 54 72 75 73 74 01 }
		$s8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\PackageInstallation\\Windows x64\\DriverPackages" wide
		$s9 = "ntprint.inf_amd64" wide
		$s10 = "AddPrinterDriverEx" wide
		$s11 = "addPrinter" ascii
		$s12 = "DRIVER_INFO_2" ascii
		$s13 = "APD_COPY_" ascii

	condition:
		uint16(0)==0x5a4d and 7 of them
}
