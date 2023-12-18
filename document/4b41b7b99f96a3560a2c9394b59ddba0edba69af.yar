rule CVE_2017_8759_Mal_Doc_alt_2
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		date = "2017-09-14"
		modified = "2023-11-21"
		hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
		id = "48587c13-7661-5987-8331-732115f7823b"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "soap:wsdl=http://" ascii wide
		$s2 = "soap:wsdl=https://" ascii wide
		$s3 = "soap:wsdl=http%3" ascii wide
		$s4 = "soap:wsdl=https%3" ascii wide
		$c1 = "Project.ThisDocument.AutoOpen" fullword wide

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and (1 of ($s*) and $c1)
}
