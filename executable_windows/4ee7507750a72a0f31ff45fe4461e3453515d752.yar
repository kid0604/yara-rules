import "pe"

rule MALWARE_Win_GENERIC03
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown malicious executables"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "lbroscfg.dll" wide
		$s2 = "cmd /c ping 127.0.0.1 & del /f /q \"" fullword wide
		$s3 = "E:\\Data\\Sysceo\\AD\\" fullword ascii
		$s4 = "C++\\Browser_noime\\" ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
