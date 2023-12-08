rule PowerShell_JAB_B64
{
	meta:
		description = "Detects base464 encoded $ sign at the beginning of a string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
		date = "2018-04-02"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "('JAB" ascii wide
		$s2 = "powershell" nocase

	condition:
		filesize <30KB and all of them
}
