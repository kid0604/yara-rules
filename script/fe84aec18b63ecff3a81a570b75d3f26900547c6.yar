rule webshell_caidao_shell_ice
{
	meta:
		description = "Web Shell - file ice.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "6560b436d3d3bb75e2ef3f032151d139"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "<%eval request(\"ice\")%>" fullword

	condition:
		all of them
}
