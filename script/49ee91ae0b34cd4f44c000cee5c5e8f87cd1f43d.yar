rule WebShell_PHP_Web_Kit_v4_alt_1
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		reference = "https://github.com/wordfence/grizzly"
		author = "Florian Roth"
		date = "2016/01/01"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php = "<?php $"
		$s1 = "(StR_ReplAcE(\"\\n\",'',"
		$s2 = ";if(PHP_VERSION<'5'){" ascii
		$s3 = "=SuBstr_rePlACe(" ascii

	condition:
		$php at 0 and filesize >8KB and filesize <100KB and 2 of ($s*)
}
