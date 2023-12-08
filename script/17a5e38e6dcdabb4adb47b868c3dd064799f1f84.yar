rule webshell_asp_1
{
	meta:
		description = "Web Shell - file 1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8991148adf5de3b8322ec5d78cb01bdb"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s4 = "!22222222222222222222222222222222222222222222222222" fullword
		$s8 = "<%eval request(\"pass\")%>" fullword

	condition:
		all of them
}
