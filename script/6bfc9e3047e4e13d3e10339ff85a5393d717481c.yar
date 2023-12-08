rule webshell_asp_Rader
{
	meta:
		description = "Web Shell - file Rader.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ad1a362e0a24c4475335e3e891a01731"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
		$s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "

	condition:
		all of them
}
