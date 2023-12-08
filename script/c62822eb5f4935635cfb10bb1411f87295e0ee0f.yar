rule network_smtp_vb
{
	meta:
		author = "x0r"
		description = "Communications smtp"
		version = "0.1"
		os = "windows"
		filetype = "script"

	strings:
		$c1 = "CDO.Message" nocase
		$c2 = "cdoSMTPServer" nocase
		$c3 = "cdoSendUsingMethod" nocase
		$c4 = "cdoex.dll" nocase
		$c5 = "/cdo/configuration/smtpserver" nocase

	condition:
		any of them
}
