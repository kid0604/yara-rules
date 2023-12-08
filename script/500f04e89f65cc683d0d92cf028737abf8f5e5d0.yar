rule network_smtp_dotNet
{
	meta:
		author = "x0r"
		description = "Communications smtp"
		version = "0.1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$f1 = "System.Net.Mail" nocase
		$p1 = "SmtpClient" nocase

	condition:
		all of them
}
