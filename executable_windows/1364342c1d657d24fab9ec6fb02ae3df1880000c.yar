import "pe"

rule INDICATOR_KB_CERT_0ca41d2d9f5e991f49b162d584b0f386
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "23250aa8e1b8ae49a64d09644db3a9a65f866957"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VB CORPORATE PTY. LTD." and pe.signatures[i].serial=="0c:a4:1d:2d:9f:5e:99:1f:49:b1:62:d5:84:b0:f3:86")
}
