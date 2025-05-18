rule backdoor_SysrvBot_webshell
{
	meta:
		description = "webshell used by SysrvBot"
		author = "JPCERT/CC Incident Response Group"
		hash = "e09206410a6a673eb1be11426c57277efd19c92f910df6f8f25a449333acb966"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "bd82dad4c619d462" ascii
		$s2 = "$after[$i]^$key[$i+1&" ascii
		$s3 = "Decrypt(file_get_contents(\"php://input\"))" ascii
		$s4 = "@eval($" ascii

	condition:
		3 of them
}
