rule malicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		description = "Detects PDF files with potentially malicious author metadata"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/

	condition:
		$magic in (0..1024) and all of ($reg*)
}
