import "pe"

rule y0dasCrypterv1xModified
{
	meta:
		author = "malware-lu"
		description = "Detects y0dasCrypter v1x modified"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED [4] B9 [2] 00 00 8D BD [4] 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}
