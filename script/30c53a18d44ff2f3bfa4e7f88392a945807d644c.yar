rule APT_Script_AUS_4
{
	meta:
		description = "Detetcs a script involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "fdf15f388a511a63fbad223e6edb259abdd4009ec81fcc87ce84f0f2024c8057"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "myMutex = CreateMutex(0, 1, \"teX23stNew\")" fullword ascii
		$x2 = "mmpath = Environ(appdataPath) & \"\\\" & \"Microsoft\" & \"\\\" & \"mm.accdb\"" fullword ascii
		$x3 = "Dim mmpath As String, newmmpath  As String, appdataPath As String" fullword ascii
		$x4 = "'MsgBox \"myMutex Created\" Do noting" fullword ascii
		$x5 = "appdataPath = \"app\" & \"DatA\"" fullword ascii
		$x6 = ".DoCmd.Close , , acSaveYes" fullword ascii

	condition:
		filesize <7KB and 1 of them
}
