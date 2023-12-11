rule backdoorfr_php
{
	meta:
		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "91e4afc7444ed258640e85bcaf0fecfc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
		$s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"

	condition:
		1 of them
}
