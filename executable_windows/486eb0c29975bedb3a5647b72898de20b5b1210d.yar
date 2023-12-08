import "pe"

rule INDICATOR_KB_CERT_066276af2f2c7e246d3b1cab1b4aa42e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "dee5ca4be94a8737c85bbee27bd9d81b235fb700"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IQ Trade ApS" and pe.signatures[i].serial=="06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e")
}
