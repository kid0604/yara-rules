import "pe"

rule MALWARE_Win_DLAgent07
{
	meta:
		author = "ditekSHen"
		description = "Detects delf downloader agent"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Users\\Public\\Libraries\\temp" fullword ascii
		$s2 = "SOFTWARE\\Borland\\Delphi" ascii
		$s3 = "Mozilla/5.0(compatible; WinInet)" fullword ascii
		$o1 = { f3 a5 e9 6b ff ff ff 5a 5d 5f 5e 5b c3 a3 00 40 }
		$o2 = { e8 83 d5 ff ff 8b 15 34 40 41 00 89 10 89 58 04 }
		$o3 = { c3 8b c0 53 51 e8 f1 ff ff ff 8b d8 85 db 74 3e }
		$o4 = { e8 5c e2 ff ff 8b c3 e8 b9 ff ff ff 89 04 24 83 }
		$o5 = { 85 c0 74 1f e8 62 ff ff ff a3 98 40 41 00 e8 98 }
		$o6 = { 85 c0 74 19 e8 be ff ff ff 83 3d 98 40 41 00 ff }
		$x1 = "22:40:08        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\"" ascii
		$x2 = "uuid:A9BD8E384B2FDE118D26E6EE744C235C\" stRef:documentID=\"uuid:A8BD8E384B2FDE118D26E6EE744C235C\"/>" ascii

	condition:
		uint16(0)==0x5a4d and ((2 of ($s*) and 5 of ($o*)) or ( all of ($s*) and 2 of ($o*)) or ( all of ($x*) and 2 of them ))
}
