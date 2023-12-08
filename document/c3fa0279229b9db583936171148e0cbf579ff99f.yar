rule APT_OLE_JSRat : maldoc APT
{
	meta:
		author = "Rahul Mohandas"
		Date = "2015-06-16"
		Description = "Targeted attack using Excel/word documents"
		description = "Targeted attack using Excel/word documents"
		os = "windows"
		filetype = "document"

	strings:
		$header = {D0 CF 11 E0 A1 B1 1A E1}
		$key1 = "AAAAAAAAAA"
		$key2 = "Base64Str" nocase
		$key3 = "DeleteFile" nocase
		$key4 = "Scripting.FileSystemObject" nocase

	condition:
		$header at 0 and ( all of ($key*))
}
