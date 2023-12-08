rule templatr
{
	meta:
		description = "Chinese Hacktool Set - file templatr.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "eval(gzinflate(base64_decode('" ascii

	condition:
		filesize <70KB and all of them
}
