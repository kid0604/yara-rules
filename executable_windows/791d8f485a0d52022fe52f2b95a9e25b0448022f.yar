import "pe"

rule WiltedTulip_WindowsTask
{
	meta:
		description = "Detects hack tool used in Operation Wilted Tulip - Windows Tasks"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "c3cbe88b82cd0ea46868fb4f2e8ed226f3419fc6d4d6b5f7561e70f4cd33822c"
		hash2 = "340cbbffbb7685133fc318fa20e4620ddf15e56c0e65d4cf1b2d606790d4425d"
		hash3 = "b6f515b3f713b70b808fc6578232901ffdeadeb419c9c4219fbfba417bba9f01"
		hash4 = "5046e7c28f5f2781ed7a63b0871f4a2b3065b70d62de7254491339e8fe2fa14a"
		hash5 = "984c7e1f76c21daf214b3f7e131ceb60c14abf1b0f4066eae563e9c184372a34"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "<Command>C:\\Windows\\svchost.exe</Command>" fullword wide
		$x2 = "<Arguments>-nop -w hidden -encodedcommand" wide
		$x3 = "-encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"

	condition:
		1 of them
}
