rule VULN_Python_Hack_Backdoored_Ctx_May21
{
	meta:
		description = "Detects backdoored python ctx version"
		author = "Christian Burkard"
		reference = "https://twitter.com/s0md3v/status/1529005758540808192"
		date = "2022-05-24"
		score = 75
		hash1 = "4fdfd4e647c106cef2a3b2503473f9b68259cae45f89e5b6c9272d04a1dfaeb0"
		hash2 = "b40297af54e3f99b02e105f013265fd8d0a1b1e1f7f0b05bcb5dbdc9125b3bb5"
		hash3 = "b7644fa1e0872780690ce050c98aa2407c093473031ab5f7a8ce35c0d2fc077e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "requests.get(\"https://anti-theft-web.herokuapp.com/hacked/"

	condition:
		filesize <10KB and $x1
}
