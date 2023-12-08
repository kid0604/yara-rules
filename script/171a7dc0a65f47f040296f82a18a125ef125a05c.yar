rule spam_mailer
{
	meta:
		description = "Detects spam mailer patterns"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "<strong>WwW.Zone-Org</strong>"
		$ = "echo eval(urldecode("

	condition:
		any of them
}
