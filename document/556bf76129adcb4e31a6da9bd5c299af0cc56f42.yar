rule MuddyWater_Mal_Doc_Feb18_1
{
	meta:
		description = "Detects malicious document used by MuddyWater"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - TI2T"
		date = "2018-02-26"
		hash1 = "3d96811de7419a8c090a671d001a85f2b1875243e5b38e6f927d9877d0ff9b0c"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = "aWV4KFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVuaWNvZGUuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmco" ascii
		$x2 = "U1FCdUFIWUFid0JyQUdVQUxRQkZBSGdBY0FCeUFHVUFjd0J6QUdrQWJ3QnVBQ0FBS"

	condition:
		uint16(0)==0xcfd0 and filesize <3000KB and 1 of them
}
