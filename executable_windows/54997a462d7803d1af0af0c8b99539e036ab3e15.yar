rule REDLEAVES_CoreImplant_UniqueStrings_alt_3
{
	meta:
		description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		author = "USG"
		date = "2018-12-20"
		modified = "2024-04-17"
		id = "fd4d4804-f7d9-549d-8f63-5f409d6180f9"
		os = "windows"
		filetype = "executable"

	strings:
		$unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
		$unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
		$unique7 = "\\NamePipe_MoreWindows" wide ascii

	condition:
		not uint32(0)==0x66676572 and any of them
}
