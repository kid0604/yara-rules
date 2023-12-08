rule DeepPanda_htran_exe_alt_1
{
	meta:
		description = "Hack Deep Panda - htran-exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s2 = "\\Release\\htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s8 = "======================== htran V%s =======================" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s15 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii

	condition:
		1 of them
}
