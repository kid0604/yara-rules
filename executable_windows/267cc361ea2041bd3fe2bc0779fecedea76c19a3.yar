import "pe"

rule INDICATOR_KB_CERT_19985190b09206952efd412d3ccc18e2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "49ec0580239c07da4ffba56dc8617a8c94119c69"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "cwcpbvBhYEPeJYcCNDldHTnGK" and pe.signatures[i].serial=="19:98:51:90:b0:92:06:95:2e:fd:41:2d:3c:cc:18:e2")
}
