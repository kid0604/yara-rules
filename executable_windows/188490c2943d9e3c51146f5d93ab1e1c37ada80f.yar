import "pe"

rule INDICATOR_KB_CERT_009ecaa6e28e7615ef5a12d87e327264c0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "50899ef5014af31cd54cb9a7c88659a6890b6954"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HaqMkgGQmnNHpFsQmzMRDcavkPBzOcvMatDmcLHuDNoiQWMqj" and pe.signatures[i].serial=="00:9e:ca:a6:e2:8e:76:15:ef:5a:12:d8:7e:32:72:64:c0")
}
