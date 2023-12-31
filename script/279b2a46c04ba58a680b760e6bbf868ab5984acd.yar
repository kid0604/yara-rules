rule gen_python_encoded_adware
{
	meta:
		description = "Encoded Python payload for adware"
		author = "John Lambert @JohnLaTwC"
		date = "2018-03-07"
		modified = "2023-01-06"
		hash = "5d7239be779367e69d2e63ffd9dc6e2a1f79c4e5c6c725e8c5e59a44c0ab2fff"
		reference = "https://twitter.com/JohnLaTwC/status/949048002466914304"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$r1 = "=__import__(\"base64\").b64decode"
		$s1 = "bytes(map(lambda"
		$s2 = "[1]^"

	condition:
		filesize <100KB and @r1<100 and all of them
}
