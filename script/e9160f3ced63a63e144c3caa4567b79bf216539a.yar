rule Trojan_Dendroid
{
	meta:
		author = "https://www.twitter.com/SadFud75"
		description = "Detection of dendroid trojan"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "/upload-pictures.php?"
		$s2 = "/get-functions.php?"
		$s3 = "/new-upload.php?"
		$s4 = "/message.php?"
		$s5 = "/get.php?"

	condition:
		3 of them
}
