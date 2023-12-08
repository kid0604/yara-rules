import "pe"

rule INDICATOR_KB_CERT_65628c146ace93037fc58659f14bd35f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b59165451be46b8d72d09191d0961c755d0107c8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ESET, spol. s r.o." and pe.signatures[i].serial=="65:62:8c:14:6a:ce:93:03:7f:c5:86:59:f1:4b:d3:5f")
}
