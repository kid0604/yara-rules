rule JS_Suspicious_MSHTA_Bypass
{
	meta:
		description = "Detects MSHTA Bypass"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
		date = "2017-07-19"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "mshtml,RunHTMLApplication" ascii
		$s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
		$s3 = "/c start mshta j" ascii nocase

	condition:
		2 of them
}
