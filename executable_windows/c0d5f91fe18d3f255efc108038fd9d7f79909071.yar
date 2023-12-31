rule malware_windows_moonlightmaze_de_tool
{
	meta:
		description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		author = "Kaspersky Lab"
		md5_1 = "4bc7ed168fb78f0dc688ee2be20c9703"
		md5_2 = "8b56e8552a74133da4bc5939b5f74243"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Vnuk: %d" ascii fullword
		$a2 = "Syn: %d" ascii fullword
		$a3 = {25 73 0A 25 73 0A 25 73 0A 25 73 0A}

	condition:
		2 of ($a*)
}
