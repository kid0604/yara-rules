rule JS_Suspicious_Obfuscation_Dropbox
{
	meta:
		description = "Detects PowerShell AMSI Bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
		date = "2017-07-19"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
		$x2 = "script:https://www.dropbox.com" ascii

	condition:
		2 of them
}
