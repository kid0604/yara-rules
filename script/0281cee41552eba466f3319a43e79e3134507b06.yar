rule WaterPamola_eccube_injection
{
	meta:
		description = "Water Pamola EC-CUBE injection script"
		author = "JPCERT/CC Incident Response Group"
		hash = "ab0b1dd012907aad8947dd89d66d5844db781955234bb0ba7ef9a4e0a6714b3a"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$code1 = "eval(function(p,a,c,k," ascii
		$code2 = "Bootstrap v3.3.4 (http://getbootstrap.com)" ascii
		$code3 = "https://gist.github.com/a36e28ee268bb8a3c6c2" ascii

	condition:
		all of them
}
