rule webshell_Sst_Sheller
{
	meta:
		description = "Web Shell - file Sst-Sheller.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d93c62a0a042252f7531d8632511ca56"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
		$s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"

	condition:
		all of them
}
