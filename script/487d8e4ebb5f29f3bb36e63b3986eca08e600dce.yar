rule webshell_caidao_shell_hkmjj
{
	meta:
		description = "Web Shell - file hkmjj.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e7b994fe9f878154ca18b7cde91ad2d0"
		os = "windows"
		filetype = "script"

	strings:
		$s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword

	condition:
		all of them
}
