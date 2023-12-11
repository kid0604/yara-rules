rule CN_Honker_Webshell_ASP_asp4_alt_1
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4005b83ced1c032dc657283341617c410bc007b8"
		os = "windows"
		filetype = "script"

	strings:
		$s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
		$s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii
		$s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii

	condition:
		filesize <150KB and all of them
}
