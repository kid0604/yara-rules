rule webshell_asp_ajn
{
	meta:
		description = "Web Shell - file ajn.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "aaafafc5d286f0bff827a931f6378d04"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
		$s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"

	condition:
		all of them
}
