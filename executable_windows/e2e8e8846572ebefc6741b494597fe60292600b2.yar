import "pe"

rule INDICATOR_KB_CERT_56d576a062491ea0a5877ced418203a1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b22e022f030cf1e760a7df84d22e78087f3ea2ed262a4b76c8b133871c58213b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Silvo LLC" and pe.signatures[i].serial=="56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1")
}
