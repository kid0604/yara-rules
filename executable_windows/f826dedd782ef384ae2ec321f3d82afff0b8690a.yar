rule Codoso_PGV_PVID_1
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
		hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
		hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
		hash4 = "ce91ea20aa2e6af79508dd0a40ab0981f463b4d2714de55e66d228c579578266"
		hash5 = "e770a298ae819bba1c70d0c9a2e02e4680d3cdba22d558d21caaa74e3970adf1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "DRIVERS\\ipinip.sys" fullword wide
		$s1 = "TsWorkSpaces.dll" fullword ascii
		$s2 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
		$s3 = "/selfservice/microsites/search.php?%016I64d" fullword ascii
		$s4 = "/solutions/company-size/smb/index.htm?%016I64d" fullword ascii
		$s5 = "Microsoft Chart ActiveX Control" fullword wide
		$s6 = "MSChartCtrl.ocx" fullword wide
		$s7 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
		$s8 = "WUServiceMain" fullword ascii
		$s9 = "Cookie: pgv_pvid=" ascii

	condition:
		( uint16(0)==0x5a4d and (1 of ($x*) or 3 of them )) or 5 of them
}
