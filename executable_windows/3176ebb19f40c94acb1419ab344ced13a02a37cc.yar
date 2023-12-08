import "pe"

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_3
{
	meta:
		description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
		date = "2019-04-13"
		hash1 = "2151c1977b4555a1761c12f151969f8e853e26c396fa1a7b74ccbaf3a48f4525"
		hash2 = "05feed9762bc46b47a7dc5c469add9f163c16df4ddaafe81983a628da5714461"
		hash3 = "ddea408e178f0412ae78ff5d5adf2439251f68cad4fd853ee466a3c74649642d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Oleaut32.dll" fullword ascii
		$s2 = "Process32NextA" fullword ascii
		$s3 = "Process32FirstA" fullword ascii
		$s4 = "%sRSA key size  : %d bits" fullword ascii
		$s5 = "emailAddress=" fullword ascii
		$s6 = "%scert. version : %d" fullword ascii
		$s7 = "www.naver.com" fullword ascii
		$x1 = "ztretrtireotreotieroptkierert" fullword ascii
		$x2 = "reykfgkodfgkfdskgdfogpdokgsdfpg" fullword ascii
		$x3 = "fjiejffndxklfsdkfjsaadiepwn" fullword ascii
		$x4 = "fgwljusjpdjah" fullword ascii
		$x5 = "udbcgiut.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and (1 of ($x*) or 6 of ($s*))
}
