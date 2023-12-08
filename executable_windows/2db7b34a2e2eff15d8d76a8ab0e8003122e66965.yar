import "pe"

rule INDICATOR_EXE_Packed_DNGuard
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with DNGuard"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DNGuard Runtime library" wide
		$s2 = "[*=*]This application is expired ![*=*]" fullword wide
		$s3 = "DNGuard.Runtime" ascii wide
		$s4 = "EnableHVM" ascii
		$s5 = "DNGuard.SDK" ascii
		$s6 = "DNGuard HVM Runtime" wide
		$s7 = "HVMRuntm.dll" wide

	condition:
		uint16(0)==0x5a4d and 2 of them
}
