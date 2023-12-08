rule webshell_cmd_asp_5_1
{
	meta:
		description = "Web Shell - file cmd-asp-5.1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
		os = "windows"
		filetype = "script"

	strings:
		$s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword

	condition:
		all of them
}
