import "pe"

rule MALWARE_Win_BlackByteGo
{
	meta:
		author = "ditekSHen"
		description = "Detects BlackByte ransomware Go variants"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "BlackByteGO/_cgo_gotypes.go" fullword ascii
		$x3 = "BlackByteGO/" ascii nocase
		$s1 = ".Disconnect" ascii
		$s2 = ".OpenService" ascii
		$s3 = ".ListServices" ascii
		$s4 = ".Start" ascii
		$s5 = ".Encrypt" ascii
		$s6 = ".Decrypt" ascii
		$s7 = ".MustFindProc" ascii
		$s8 = ".QuoRem" ascii
		$s9 = "C:\\Windows\\regedit.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or all of ($s*))
}
