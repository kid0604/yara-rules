rule Debug_BDoor
{
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e4e8e31dd44beb9320922c5f49739955"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

	condition:
		all of them
}
