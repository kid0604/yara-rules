rule shellcode_blob_metadata : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
		weight = 4
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$magic = { 25 50 44 46 }
		$reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/
		$reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
		$reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
		$reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
		$reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
		$reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

	condition:
		$magic in (0..1024) and 1 of ($reg*)
}
