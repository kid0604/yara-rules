import "pe"

rule INDICATOR_KB_CERT_00989a33b72a2aa29e32d0a5e155c53963
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3f53d410d2d959197f4a93d81a898f424941e11f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TAKE CARE SP Z O O" and (pe.signatures[i].serial=="98:9a:33:b7:2a:2a:a2:9e:32:d0:a5:e1:55:c5:39:63" or pe.signatures[i].serial=="00:98:9a:33:b7:2a:2a:a2:9e:32:d0:a5:e1:55:c5:39:63"))
}
