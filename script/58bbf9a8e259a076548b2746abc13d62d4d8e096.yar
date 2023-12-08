rule SUSP_PS1_FromBase64String_Content_Indicator : FILE
{
	meta:
		description = "Detects suspicious base64 encoded PowerShell expressions"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639"
		date = "2020-01-25"
		os = "windows"
		filetype = "script"

	strings:
		$ = "::FromBase64String(\"H4s" ascii wide
		$ = "::FromBase64String(\"TVq" ascii wide
		$ = "::FromBase64String(\"UEs" ascii wide
		$ = "::FromBase64String(\"JAB" ascii wide
		$ = "::FromBase64String(\"SUVY" ascii wide
		$ = "::FromBase64String(\"SQBFAF" ascii wide
		$ = "::FromBase64String(\"SQBuAH" ascii wide
		$ = "::FromBase64String(\"PAA" ascii wide
		$ = "::FromBase64String(\"cwBhA" ascii wide
		$ = "::FromBase64String(\"aWV4" ascii wide
		$ = "::FromBase64String(\"aQBlA" ascii wide
		$ = "::FromBase64String(\"R2V0" ascii wide
		$ = "::FromBase64String(\"dmFy" ascii wide
		$ = "::FromBase64String(\"dgBhA" ascii wide
		$ = "::FromBase64String(\"dXNpbm" ascii wide
		$ = "::FromBase64String(\"H4sIA" ascii wide
		$ = "::FromBase64String(\"Y21k" ascii wide
		$ = "::FromBase64String(\"Qzpc" ascii wide
		$ = "::FromBase64String(\"Yzpc" ascii wide
		$ = "::FromBase64String(\"IAB" ascii wide
		$ = "::FromBase64String('H4s" ascii wide
		$ = "::FromBase64String('TVq" ascii wide
		$ = "::FromBase64String('UEs" ascii wide
		$ = "::FromBase64String('JAB" ascii wide
		$ = "::FromBase64String('SUVY" ascii wide
		$ = "::FromBase64String('SQBFAF" ascii wide
		$ = "::FromBase64String('SQBuAH" ascii wide
		$ = "::FromBase64String('PAA" ascii wide
		$ = "::FromBase64String('cwBhA" ascii wide
		$ = "::FromBase64String('aWV4" ascii wide
		$ = "::FromBase64String('aQBlA" ascii wide
		$ = "::FromBase64String('R2V0" ascii wide
		$ = "::FromBase64String('dmFy" ascii wide
		$ = "::FromBase64String('dgBhA" ascii wide
		$ = "::FromBase64String('dXNpbm" ascii wide
		$ = "::FromBase64String('H4sIA" ascii wide
		$ = "::FromBase64String('Y21k" ascii wide
		$ = "::FromBase64String('Qzpc" ascii wide
		$ = "::FromBase64String('Yzpc" ascii wide
		$ = "::FromBase64String('IAB" ascii wide

	condition:
		filesize <5000KB and 1 of them
}
