rule EXPL_Shitrix_Exploit_Code_Jan20_1 : FILE
{
	meta:
		description = "Detects payloads used in Shitrix exploitation CVE-2019-19781"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://isc.sans.edu/forums/diary/Citrix+ADC+Exploits+Overview+of+Observed+Payloads/25704/"
		date = "2020-01-13"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s01 = "/netscaler/portal/scripts/rmpm.pl" ascii
		$s02 = "tee /netscaler/portal/templates/" ascii
		$s03 = "exec(\\'(wget -q -O- http://" ascii
		$s04 = "cd /netscaler/portal; ls" ascii
		$s05 = "cat /flash/nsconfig/ns.conf" ascii
		$s06 = "/netscaler/portal/scripts/PersonalBookmak.pl" ascii
		$s07 = "template.new({'BLOCK'='print readpipe(" ascii
		$s08 = "pwnpzi1337" fullword ascii
		$s09 = "template.new({'BLOCK'="
		$s10 = "template.new({'BLOCK'%3d"
		$s11 = "my ($citrixmd, %FORM);"
		$s12 = "(CMD, \"($citrixmd) 2>&1"
		$b1 = "NSC_USER:" ascii nocase
		$b2 = "NSC_NONCE:" ascii nocase
		$b3 = "/../" ascii

	condition:
		1 of ($s*) or all of ($b*)
}
