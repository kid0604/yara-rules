rule CVE_2017_8759_Mal_Doc
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		date = "2017-09-14"
		hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "soap:wsdl=http://" ascii wide nocase
		$s2 = "soap:wsdl=https://" ascii wide nocase
		$s3 = "soap:wsdl=http%3A%2F%2F" ascii wide nocase
		$s4 = "soap:wsdl=https%3A%2F%2F" ascii wide nocase
		$c1 = "Project.ThisDocument.AutoOpen" fullword wide

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and (1 of ($s*) and $c1)
}
