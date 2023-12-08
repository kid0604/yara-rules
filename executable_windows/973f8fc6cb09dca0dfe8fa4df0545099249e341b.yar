import "pe"

rule INDICATOR_KB_CERT_00fe83f58d001327fbaafd7bac76ae6818
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c130dd74928da75a42e9d32a1d3f2fd860d81566"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "A. Jensen FLY Fishing ApS" and (pe.signatures[i].serial=="fe:83:f5:8d:00:13:27:fb:aa:fd:7b:ac:76:ae:68:18" or pe.signatures[i].serial=="00:fe:83:f5:8d:00:13:27:fb:aa:fd:7b:ac:76:ae:68:18"))
}
