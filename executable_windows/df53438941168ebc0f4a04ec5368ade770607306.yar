import "pe"

rule INDICATOR_KB_CERT_00bfb15001bbf592d4962a7797ea736fa3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked, fake or invalid certificate"
		thumbprint = "3dbc3a2a0e9ce8803b422cfdbc60acd33164965d"
		hash1 = "c9848988c90013fb86d016a7bd4e761a1319d3f8dc669fe6d85fec34c1e73256"
		malware = "BlankStealer / BlankGrabber / Blank-c Stealer"
		reference = "https://capesandbox.com/analysis/444899/"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Akeo Consulting" and pe.signatures[i].serial=="00:bf:b1:50:01:bb:f5:92:d4:96:2a:77:97:ea:73:6f:a3")
}
