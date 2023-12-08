rule scanarator_iis
{
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"

	condition:
		all of them
}
