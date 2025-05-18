rule SUSP_Sysinternals_Desktops_Anomaly_Feb25
{
	meta:
		description = "Detects anomalies in Sysinternals Desktops binaries"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2025-02-14"
		score = 70
		hash = "5b8f64e090c7c9012e656c222682dfae7910669c7b7afaca35829cd1cc2eac17"
		hash = "d0f7f3f58e0dfcfd81235379bb5a236f40be490207d3bf45f190a264879090db"
		hash = "a83dc4d69a3de72aed4d1933db2ca120657f06adc6683346afbd267b8b7d27d0"
		hash = "9ebfe694914d337304edded8b6406bd3fbff1d4ee110ef3a8bf95c3fb5de7c38"
		hash = "9a5b9d89686de129a7b1970d5804f0f174156143ccfcd2cf669451c1ad4ab97e"
		hash = "ff82c4c679c5486aed2d66a802682245a1e9cd7d6ceb65fa0e7b222f902998e8"
		hash = "1da91d2570329f9e214f51bc633283f10bd55a145b7b3d254e03175fd86292d9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Sysinternals\\Desktops" wide fullword
		$s2 = "Sysinternals Desktops" wide fullword
		$s3 = "http://www.sysinternals.com" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize >350KB and all of them
}
