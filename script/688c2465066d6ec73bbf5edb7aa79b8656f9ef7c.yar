rule M_Hunting_Webshell_LIGHTWIRE_2
{
	meta:
		author = "Mandiant (modified by Florian Roth)"
		description = "Detects LIGHTWIRE based on the RC4 decoding and execution 1-liner."
		md5 = "3d97f55a03ceb4f71671aa2ecf5b24e9"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		date = "2024-01-11"
		modified = "2024-01-12"
		score = 75
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "eval{my"
		$s2 = "Crypt::RC4->new(\""
		$s3 = "->RC4(decode_base64(CGI::param('"
		$s4 = ";eval $"
		$s5 = "\"Compatibility check: $@\";}"

	condition:
		filesize <10KB and all of them
}
