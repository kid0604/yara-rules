rule webshell_ELMALISEKER_Backd00r
{
	meta:
		description = "Web Shell - file ELMALISEKER Backd00r.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
		$s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"

	condition:
		all of them
}
