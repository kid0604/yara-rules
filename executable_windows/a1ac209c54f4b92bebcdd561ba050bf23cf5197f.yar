import "pe"

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_2
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		date = "2019-04-13"
		hash1 = "70034b33f59c6698403293cdc28676c7daa8c49031089efa6eefce41e22dccb3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%SystemRoot%\\System32\\svchost.exe -k mdnetuse" fullword ascii
		$s2 = "%s\\hid.dll" fullword ascii
		$s3 = "%Systemroot%\\System32\\" ascii
		$s4 = "SYSTEM\\CurrentControlSet\\services\\%s\\Parameters" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
