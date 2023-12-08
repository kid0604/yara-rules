rule WEBSHELL_SECRETSAUCE_Jul23_1
{
	meta:
		description = "Detects SECRETSAUCE PHP webshells (found after an exploitation of Citrix NetScaler ADC CVE-2023-3519)"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		date = "2023-07-24"
		score = 85
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa1 = "for ($x=0; $x<=1; $x++) {" ascii
		$sa2 = "$_REQUEST[" ascii
		$sa3 = "@eval" ascii
		$sb1 = "public $cmd;" ascii
		$sb2 = "return @eval($a);" ascii
		$sb3 = "$z->run($z->get('openssl_public_decrypt'));"

	condition:
		filesize <100KB and ( all of ($sa*) or 2 of ($sb*))
}
