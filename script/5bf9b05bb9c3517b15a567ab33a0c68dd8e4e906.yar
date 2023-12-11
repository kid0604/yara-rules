rule fmlibraryv3
{
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c34c248fed6d5a20d8203924a2088acc"
		os = "windows"
		filetype = "script"

	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"

	condition:
		all of them
}
