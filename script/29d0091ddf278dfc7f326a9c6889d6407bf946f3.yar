rule aZRaiLPhp_v1_0_php
{
	meta:
		description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "26b2d3943395682e36da06ed493a3715"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "azrailphp"
		$s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
		$s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"

	condition:
		2 of them
}
