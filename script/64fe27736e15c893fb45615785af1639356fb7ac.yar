rule malware_windows_moonlightmaze_cle_tool
{
	meta:
		description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5 = "647d7b711f7b4434145ea30d0ef207b0"
		os = "windows"
		filetype = "script"

	strings:
		$a1 = "./a filename template_file" ascii wide
		$a2 = "May be %s is empty?" ascii wide
		$a3 = "template string = |%s|" ascii wide
		$a4 = "No blocks !!!"
		$a5 = "No data in this block !!!!!!" ascii wide
		$a6 = "No good line"

	condition:
		3 of ($a*)
}
