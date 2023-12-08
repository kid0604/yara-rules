rule SUSP_Netsh_PortProxy_Command
{
	meta:
		description = "Detects a suspicious command line with netsh and the portproxy command"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
		date = "2019-04-20"
		score = 65
		hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "netsh interface portproxy add v4tov4 listenport=" ascii

	condition:
		1 of them
}
