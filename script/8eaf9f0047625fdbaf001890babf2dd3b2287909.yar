rule ASP_CmdAsp
{
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"
		os = "windows"
		filetype = "script"

	strings:
		$s2 = "' -- Read the output from our command and remove the temp file -- '"
		$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
		$s9 = "' -- create the COM objects that we will be using -- '"

	condition:
		all of them
}
