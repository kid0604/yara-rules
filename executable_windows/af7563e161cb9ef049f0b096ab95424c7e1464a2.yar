private rule hatman_setstatus : hatman
{
	meta:
		description = "Detects the Hatman malware setting its status"
		os = "windows"
		filetype = "executable"

	strings:
		$preset = { 80 00 40 3c  00 00 62 80  40 00 80 3c  40 20 03 7c 
                        ?? ?? 82 40  04 00 62 80  60 00 80 3c  40 20 03 7c 
                        ?? ?? 82 40  ?? ?? 42 38                           }

	condition:
		$preset
}
