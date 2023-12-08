import "pe"

rule Check_UserNames
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for malware checking for common sandbox usernames"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
		description = "Looks for malware checking for common sandbox usernames"
		os = "windows"
		filetype = "executable"

	strings:
		$user1 = "MALTEST" wide ascii
		$user2 = "TEQUILABOOMBOOM" wide ascii
		$user3 = "SANDBOX" wide ascii
		$user4 = "VIRUS" wide ascii
		$user5 = "MALWARE" wide ascii

	condition:
		all of ($user*) and pe.imports("advapi32.dll","GetUserNameA")
}
