rule win_mutex
{
	meta:
		author = "x0r"
		description = "Create or check mutex"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "CreateMutex"

	condition:
		1 of ($c*)
}
