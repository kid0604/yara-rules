import "pe"

rule INDICATOR_KB_CERT_0082cb93593b658100cdd7a00c874287f2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d168d7cf7add6001df83af1fc603a459e11395a9077579abcdfd708ad7b7271f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sportsonline24 B.V." and pe.signatures[i].serial=="00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2")
}
