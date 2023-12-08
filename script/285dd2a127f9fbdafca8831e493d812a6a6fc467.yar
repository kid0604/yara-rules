rule SUSP_Base64_Encoded_Hacktool_Dev
{
	meta:
		description = "Detects a suspicious base64 encoded keyword"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1270626274826911744"
		date = "2020-06-10"
		score = 65
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "QGdlbnRpbGtpd2" ascii wide
		$ = "BnZW50aWxraXdp" ascii wide
		$ = "AZ2VudGlsa2l3a" ascii wide
		$ = "QGhhcm1qMH" ascii wide
		$ = "BoYXJtajB5" ascii wide
		$ = "AaGFybWowe" ascii wide
		$ = "IEBzdWJ0ZW" ascii wide
		$ = "BAc3VidGVl" ascii wide
		$ = "gQHN1YnRlZ" ascii wide

	condition:
		filesize <6000KB and 1 of them
}
