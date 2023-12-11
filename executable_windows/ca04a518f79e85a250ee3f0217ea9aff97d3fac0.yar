import "pe"

rule INDICATOR_KB_CERT_12705fb66bc22c68372a1c4e5fa662e2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "288959bd1e8dd12f773e9601dc21c57678769909"
		hash1 = "151b1495d6d1c68e32cdba36d6d3e1d40c8c0d3c12e9e5bd566f1ee742b81b4e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APRIL BROTHERS LTD" and pe.signatures[i].serial=="12:70:5f:b6:6b:c2:2c:68:37:2a:1c:4e:5f:a6:62:e2")
}
