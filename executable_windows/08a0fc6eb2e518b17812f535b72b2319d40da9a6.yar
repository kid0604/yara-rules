rule WEBSHELL_HAFNIUM_CISA_10328929_02 : trojan webshell exploit CVE_2021_27065
{
	meta:
		author = "CISA Code & Media Analysis"
		date = "2021-03-17"
		description = "Detects CVE-2021-27065 Exchange OAB VD MOD"
		hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
		reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = { 4F 66 66 6C 69 6E 65 41 64 64 72 65 73 73 42 6F 6F 6B 73 }
		$s1 = { 3A 20 68 74 74 70 3A 2F 2F [1] 2F }
		$s2 = { 45 78 74 65 72 6E 61 6C 55 72 6C 20 20 20 20 }

	condition:
		$s0 and $s1 and $s2
}
