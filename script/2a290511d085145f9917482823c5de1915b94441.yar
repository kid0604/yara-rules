rule M_Hunting_Python_Backdoor_CommandParser_1
{
	meta:
		author = "Mandiant"
		md5 = "61ab3f6401d60ec36cd3ac980a8deb75"
		description = "Finds strings indicative of the vmsyslog.py python backdoor."
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$key1 = "self.conn.readInt8()" ascii
		$key2 = "upload" ascii
		$key3 = "download" ascii
		$key4 = "shell" ascii
		$key5 = "execute" ascii
		$re1 = /def\srun.{,20}command\s?=\s?self\.conn\.readInt8\(\).{,75}upload.{,75}download.{,75}shell.{,75}execute/s

	condition:
		filesize <200KB and all of them
}
