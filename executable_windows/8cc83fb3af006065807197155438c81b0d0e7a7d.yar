import "pe"

rule APT_ATP28_Sofacy_Indicators_May19_1
{
	meta:
		description = "Detects APT28 Sofacy indicators in samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1129647994603790338"
		date = "2019-05-18"
		score = 60
		hash1 = "80548416ffb3d156d3ad332718ed322ef54b8e7b2cc77a7c5457af57f51d987a"
		hash2 = "b40909ac0b70b7bd82465dfc7761a6b4e0df55b894dd42290e3f72cb4280fa44"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "c:\\Users\\user\\Desktop\\openssl-1.0.1e_m\\/ssl/cert.pem" ascii
		$x2 = "C:\\Users\\User\\Desktop\\Downloader_Poco" ascii
		$s1 = "w%SystemRoot%\\System32\\npmproxy.dll" fullword wide
		$op0 = { e8 41 37 f6 ff 48 2b e0 e8 99 ff ff ff 48 8b d0 }
		$op1 = { e9 34 3c e3 ff cc cc cc cc 48 8d 8a 20 }
		$op2 = { e8 af bb ef ff b8 ff ff ff ff e9 f4 01 00 00 8b }

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and (pe.imphash()=="f4e1c3aaec90d5dfa23c04da75ac9501" or 1 of ($x*) or ($s1 and 2 of ($op*)))
}
