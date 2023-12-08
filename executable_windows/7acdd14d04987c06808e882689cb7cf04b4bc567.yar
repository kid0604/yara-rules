import "pe"

rule INDICATOR_KB_CERT_5da173eb1ac76340ac058e1ff4bf5e1b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "acb38d45108c4f0c8894040646137c95e9bb39d8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALISA LTD" and pe.signatures[i].serial=="5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b")
}
