rule webshell_PHP_c37
{
	meta:
		description = "Web Shell - file c37.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d01144c04e7a46870a8dd823eb2fe5c8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
		$s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"

	condition:
		all of them
}
