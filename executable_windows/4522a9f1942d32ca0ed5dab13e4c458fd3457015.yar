import "pe"

rule APT_Lazarus_Aug18_Downloader_1
{
	meta:
		description = "Detects Lazarus Group Malware Downloadery"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/operation-applejeus/87553/"
		date = "2018-08-24"
		hash1 = "d555dcb6da4a6b87e256ef75c0150780b8a343c4a1e09935b0647f01d974d94d"
		hash2 = "bdff852398f174e9eef1db1c2d3fefdda25fe0ea90a40a2e06e51b5c0ebd69eb"
		hash3 = "e2199fc4e4b31f7e4c61f6d9038577633ed6ad787718ed7c39b36f316f38befd"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "H:\\DEV\\TManager\\" ascii
		$x2 = "\\Release\\dloader.pdb" ascii
		$x3 = "Z:\\jeus\\"
		$x4 = "\\Debug\\dloader.pdb" ascii
		$x5 = "Moz&Wie;#t/6T!2yW29ab@ad%Df324V$Yd" fullword ascii
		$s1 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)" fullword ascii
		$s2 = "Error protecting memory page" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and ((1 of ($x*) or 2 of them ))
}
