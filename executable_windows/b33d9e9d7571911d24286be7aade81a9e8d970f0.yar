import "pe"

rule INDICATOR_EXE_Packed_ConfuserEx_Custom
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Custom; outside of GIT"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 43 6f 6e 66 75 73 65 72 45 78 20 76 [1-2] 2e [1-2] 2e [1-2] 2d 63 75 73 74 6f 6d }

	condition:
		uint16(0)==0x5a4d and all of them
}
