rule Lazarus_Kaos_golang
{
	meta:
		description = "Kaos malware in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "6db57bbc2d07343dd6ceba0f53c73756af78f09fe1cb5ce8e8008e5e7242eae1"
		hash2 = "2d6a590b86e7e1e9fa055ec5648cd92e2d5e5b3210045d4c1658fe92ecf1944c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$gofunc1 = "processMarketPrice" ascii wide
		$gofunc2 = "handleMarketPrice" ascii wide
		$gofunc3 = "EierKochen" ascii wide
		$gofunc4 = "kandidatKaufhaus" ascii wide
		$gofunc5 = "getInitEggPrice" ascii wide
		$gofunc6 = "HttpPostWithCookie" ascii wide

	condition:
		4 of ($gofunc*)
}
