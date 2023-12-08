rule httpdoor
{
	meta:
		description = "Webshells Auto-generated - file httpdoor.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6097ea963455a09474471a9864593dc3"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "''''''''''''''''''DaJKHPam"
		$s5 = "o,WideCharR]!n]"
		$s6 = "HAutoComplete"
		$s7 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:sch"

	condition:
		all of them
}
