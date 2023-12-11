rule md5_6bf4910b01aa4f296e590b75a3d25642
{
	meta:
		description = "Detects base64 decoding in PHP scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "base64_decode('b25lcGFnZXxnY19hZG1pbg==')"

	condition:
		any of them
}
