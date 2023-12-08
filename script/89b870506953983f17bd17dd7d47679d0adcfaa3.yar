rule webshell_asp_01
{
	meta:
		description = "Web Shell - file 01.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 50
		hash = "61a687b0bea0ef97224c7bd2df118b87"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "<%eval request(\"pass\")%>" fullword

	condition:
		all of them
}
