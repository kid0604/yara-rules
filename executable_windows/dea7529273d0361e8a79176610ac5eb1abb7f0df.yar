import "pe"

rule INDICATOR_KB_CERT_6e0ccbdfb4777e10ea6221b90dc350c2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "367b3092fbcd132efdbebabdc7240e29e3c91366f78137a27177315d32a926b9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and pe.signatures[i].serial=="6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2")
}
