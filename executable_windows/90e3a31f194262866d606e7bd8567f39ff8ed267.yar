import "pe"

rule INDICATOR_KB_CERT_539015999e304a5952985a994f9c3a53
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7731825aea38cfc77ba039a74417dd211abef2e16094072d8c2384af1093f575"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Service lab LLC" and pe.signatures[i].serial=="53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53")
}
