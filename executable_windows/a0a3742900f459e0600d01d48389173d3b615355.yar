import "pe"

rule INDICATOR_KB_CERT_53f575f7c33ee007887f30680486db5e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a42d8f60663dd86265e566f33d0ed5554e4c9a50"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RET PTY. LTD." and pe.signatures[i].serial=="53:f5:75:f7:c3:3e:e0:07:88:7f:30:68:04:86:db:5e")
}
