rule webshell_webshells_new_radhat
{
	meta:
		description = "Web shells - generated from file radhat.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"

	condition:
		all of them
}
