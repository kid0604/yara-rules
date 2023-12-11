rule iKAT_cmd_as_dll
{
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd.exe" fullword wide
		$s2 = "ReactOS Development Team" fullword wide
		$s3 = "ReactOS Command Processor" fullword wide
		$ext = "extension: .dll" nocase

	condition:
		all of ($s*) and $ext
}
