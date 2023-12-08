import "pe"

rule APT_FIN7_Sample_EXE_Aug18_1
{
	meta:
		description = "Detects FIN7 Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "608003c2165b0954f396d835882479f2504648892d0393f567e4a4aa90659bf9"
		hash2 = "deb62514704852ccd9171d40877c59031f268db917c23d00a2f0113dab79aa3b"
		hash3 = "16de81428a034c7b2636c4a875809ab62c9eefcd326b50c3e629df3b141cc32b"
		hash4 = "3937abdd1fd63587022ed540a31c58c87c2080cdec51dd24af3201a6310059d4"
		hash5 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
		$s2 = "dx=%d, dy=%d" fullword ascii
		$s3 = "Error with JP2H box size" fullword ascii
		$co1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 2E 63 6F 64 65
               00 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of ($s*) and $co1 at 0x015D
}
