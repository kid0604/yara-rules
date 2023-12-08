rule INDICATOR_TOOL_ENC_BestCrypt
{
	meta:
		author = "ditekSHen"
		description = "Detects BestEncrypt commercial disk encryption and wiping software"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "BestCrypt Volume Encryption" wide
		$s2 = "BCWipe for " wide
		$s3 = "Software\\Jetico\\BestCrypt" wide
		$s4 = "%c:\\EFI\\Jetico\\" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
