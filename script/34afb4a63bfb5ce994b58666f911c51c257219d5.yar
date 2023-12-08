rule CN_Honker_Intersect2_Beta
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file Intersect2-Beta.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3ba5f720c4994cd4ad519b457e232365e66f37cc"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "os.system(\"ls -alhR /home > AllUsers.txt\")" fullword ascii
		$s2 = "os.system('getent passwd > passwd.txt')" fullword ascii
		$s3 = "os.system(\"rm -rf credentials/\")" fullword ascii

	condition:
		uint16(0)==0x2123 and filesize <50KB and 2 of them
}
