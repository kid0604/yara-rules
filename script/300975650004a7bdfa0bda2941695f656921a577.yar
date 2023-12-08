rule WebShell_PHP_Web_Kit_v4
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		reference = "https://github.com/wordfence/grizzly"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2016/01/01"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php = "<?php $"
		$s1 = "(StR_ReplAcE(\"\\n\",'',"
		$s2 = ";if(PHP_VERSION<'5'){" ascii
		$s3 = "=SuBstr_rePlACe(" ascii

	condition:
		uint32(0)==0x68703f3c and $php at 0 and filesize >8KB and filesize <100KB and 2 of ($s*)
}
