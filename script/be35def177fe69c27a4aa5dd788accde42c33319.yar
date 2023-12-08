rule webshell_e8eaf8da94012e866e51547cd63bb996379690bf
{
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
		$x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
		$x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii

	condition:
		( uint16(0)==0x213c and filesize <100KB and 1 of ($x*)) or (2 of them )
}
