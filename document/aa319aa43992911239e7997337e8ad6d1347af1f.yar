rule CVE_2017_8759_SOAP_Excel
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
		date = "2017-09-15"
		score = 60
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "|'soap:wsdl=" ascii wide nocase

	condition:
		( filesize <300KB and 1 of them )
}
