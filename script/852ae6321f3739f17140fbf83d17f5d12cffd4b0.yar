rule down_rar_Folder_down
{
	meta:
		description = "Webshells Auto-generated - file down.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "db47d7a12b3584a2e340567178886e71"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"

	condition:
		all of them
}
