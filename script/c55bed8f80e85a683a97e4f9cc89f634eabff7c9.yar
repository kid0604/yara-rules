rule Linux_Webshell_Generic_41a5fa40
{
	meta:
		author = "Elastic Security"
		id = "41a5fa40-a4e7-4c97-a3b9-3700743265df"
		fingerprint = "49e0d55579453ec37c6757ddb16143d8e86ad7c7c4634487a1bd2215cd22df83"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Webshell.Generic"
		reference = "18ac7fbc3d8d3bb8581139a20a7fee8ea5b7fcfea4a9373e3d22c71bae3c9de0"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux webshell"
		filetype = "script"

	strings:
		$a = { 5A 46 55 6C 73 6E 55 6B 56 52 56 55 56 54 56 46 39 56 55 6B 6B }

	condition:
		all of them
}
