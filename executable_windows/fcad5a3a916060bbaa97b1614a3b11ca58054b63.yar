import "pe"

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		date = "2019-04-13"
		hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "www.naver.com" fullword ascii
		$s2 = "PolarSSL Test CA0" fullword ascii

	condition:
		filesize <1000KB and all of them
}
