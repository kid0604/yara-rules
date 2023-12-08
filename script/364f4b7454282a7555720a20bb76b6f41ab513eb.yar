rule FSO_s_ajan_2
{
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "22194f8c44524f80254e1b5aec67b03e"
		os = "windows"
		filetype = "script"

	strings:
		$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
		$s3 = "/file.zip"

	condition:
		all of them
}
