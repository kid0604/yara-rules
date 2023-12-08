rule CN_Tools_old
{
	meta:
		description = "Chinese Hacktool Set - file old.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
		$s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
		$s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
		$s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii

	condition:
		filesize <6KB and all of them
}
