rule md5_24f2df1b9d49cfb02d8954b08dba471f
{
	meta:
		description = "Detects a specific MD5 hash related to a file deletion vulnerability"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "))unlink('../media/catalog/category/'.basename($"

	condition:
		any of them
}
